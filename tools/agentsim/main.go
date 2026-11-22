// Command agentsim simulates EasyRMM agents for load and soak tests.
//
// Each simulated device enrolls with its own Ed25519 key, then does what the
// real agent does, over its own TLS connection:
//   - a heartbeat with facts and metrics every heartbeatSeconds;
//   - an inventory upload when the server's hash differs from its own;
//   - a job long poll held open at all times.
//
// A delivered job is checked against the pinned job-signing key, started,
// and reported as succeeded. Nothing is run: agentsim is a test tool and is
// not part of a release.
//
//	agentsim -server https://127.0.0.2 -ca-file ca.pem -token ert_… \
//	    -devices 2000 -state sim.json -duration 1h -out summary.json
//
// Devices enrolled earlier are read from -state and not enrolled again.
// Every -report it prints, per request type: the count, the errors by code,
// and latency percentiles over that interval. -out receives the same for
// the whole run as JSON.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	mrand "math/rand/v2"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/paulmataruso/easyrmm/agent/client"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

const version = "agentsim"

type options struct {
	server, caFile, token, state, out, prefix string
	devices, packages                         int
	enrollRate                                float64
	duration, report                          time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.server, "server", "", "the server's public URL")
	flag.StringVar(&o.caFile, "ca-file", "", "PEM certificate authority to trust instead of the system's")
	flag.StringVar(&o.token, "token", "", "deployment token for devices not yet in -state (or EASYRMM_TOKEN)")
	flag.StringVar(&o.state, "state", "agentsim.json", "file keeping the simulated devices' identities")
	flag.StringVar(&o.out, "out", "", "file for the run's summary (JSON)")
	flag.StringVar(&o.prefix, "prefix", "sim", "host name prefix of the simulated devices")
	flag.IntVar(&o.devices, "devices", 100, "number of devices")
	flag.IntVar(&o.packages, "packages", 300, "packages in each device's inventory")
	flag.Float64Var(&o.enrollRate, "enroll-rate", 4, "enrollments per second (the server allows 4 per address after a burst)")
	flag.DurationVar(&o.duration, "duration", 10*time.Minute, "how long to run once every device is enrolled")
	flag.DurationVar(&o.report, "report", 30*time.Second, "interval between progress reports")
	flag.Parse()
	if o.token == "" {
		o.token = os.Getenv("EASYRMM_TOKEN")
	}
	if o.server == "" || o.devices < 1 {
		flag.Usage()
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, o); err != nil {
		log.Fatal(err)
	}
}

// identity is what -state keeps for a device.
type identity struct {
	ID       string `json:"id"`
	Seed     []byte `json:"seed"`
	Hostname string `json:"hostname"`
	JobKey   string `json:"jobKey"`
}

func run(ctx context.Context, o options) error {
	ids, err := loadState(o.state)
	if err != nil {
		return err
	}
	st := newStats()
	if len(ids) < o.devices {
		if o.token == "" {
			return fmt.Errorf("%d devices to enroll and no -token", o.devices-len(ids))
		}
		ids, err = enrollAll(ctx, o, ids, st)
		if err != nil {
			return err
		}
	}
	ids = ids[:o.devices]
	log.Printf("running %d devices for %s", len(ids), o.duration)

	runCtx, cancel := context.WithTimeout(ctx, o.duration)
	defer cancel()
	var wg sync.WaitGroup
	for i, id := range ids {
		d, err := newDevice(o, i, id, st)
		if err != nil {
			return err
		}
		wg.Go(func() { d.run(runCtx) })
	}
	ticker := time.NewTicker(o.report)
	defer ticker.Stop()
	started := time.Now()
	for done := false; !done; {
		select {
		case <-runCtx.Done():
			done = true
		case <-ticker.C:
			log.Printf("after %s, %d devices polling:\n%s", time.Since(started).Round(time.Second), st.polling.Load(), st.interval())
		}
	}
	wg.Wait()
	sum := st.summary(len(ids), time.Since(started))
	log.Printf("summary:\n%s", st.interval())
	if o.out != "" {
		b, err := json.MarshalIndent(sum, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(o.out, append(b, '\n'), 0o600)
	}
	return nil
}

func loadState(path string) ([]identity, error) {
	b, err := os.ReadFile(path) //nolint:gosec // a path the operator chose
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []identity
	return ids, json.Unmarshal(b, &ids)
}

func saveState(path string, ids []identity) error {
	b, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// enrollAll enrolls the missing devices at the given rate, keeping each in
// -state as soon as it is enrolled.
func enrollAll(ctx context.Context, o options, ids []identity, st *stats) ([]identity, error) {
	c, err := client.New(client.Options{Server: o.server, CAFile: o.caFile, Version: version})
	if err != nil {
		return nil, err
	}
	every := time.Duration(float64(time.Second) / o.enrollRate)
	log.Printf("enrolling %d devices, one every %s", o.devices-len(ids), every)
	for len(ids) < o.devices {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		key := ed25519.NewKeyFromSeed(seed)
		host := fmt.Sprintf("%s-%05d", o.prefix, len(ids)+1)
		for {
			start := time.Now()
			resp, err := c.Enroll(ctx, o.token, key.Public().(ed25519.PublicKey), facts(host))
			st.record("enroll", time.Since(start), err)
			if err == nil && resp.DeviceID != "" {
				ids = append(ids, identity{ID: resp.DeviceID, Seed: seed, Hostname: host, JobKey: resp.JobKey})
				break
			}
			if err == nil {
				return nil, errors.New("the token needs approval; use a token without approval")
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if code := client.Code(err); code != "rate_limited" {
				return nil, fmt.Errorf("enrolling %s: %w", host, err)
			}
			sleep(ctx, time.Second)
		}
		if len(ids)%100 == 0 || len(ids) == o.devices {
			if err := saveState(o.state, ids); err != nil {
				return nil, err
			}
			log.Printf("%d enrolled", len(ids))
		}
		sleep(ctx, every)
	}
	return ids, nil
}

func facts(host string) agentproto.Facts {
	return agentproto.Facts{
		Hostname: host, OS: "Ubuntu 24.04.3 LTS", Platform: "linux", Arch: "amd64", AgentVersion: version,
	}
}

type device struct {
	n      int
	id     identity
	c      *client.Client
	st     *stats
	jobKey ed25519.PublicKey
	inv    []byte
	hash   string
}

func newDevice(o options, n int, id identity, st *stats) (*device, error) {
	// Each device gets its own client, and so its own connection.
	c, err := client.New(client.Options{Server: o.server, CAFile: o.caFile, Version: version})
	if err != nil {
		return nil, err
	}
	c.SetIdentity(id.ID, ed25519.NewKeyFromSeed(id.Seed))
	d := &device{n: n, id: id, c: c, st: st}
	if id.JobKey != "" {
		if d.jobKey, err = agentproto.DecodeKey(id.JobKey); err != nil {
			return nil, err
		}
	}
	inv := inventory(n, id.Hostname, o.packages)
	if d.inv, err = json.Marshal(inv); err != nil {
		return nil, err
	}
	d.hash = inv.Hash()
	return d, nil
}

func (d *device) run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { d.poll(ctx) })
	// A fleet's heartbeats are spread over the interval, not in step.
	interval := time.Minute
	sleep(ctx, time.Duration(random(float64(interval))))
	for ctx.Err() == nil {
		start := time.Now()
		resp, err := d.c.Heartbeat(ctx, agentproto.HeartbeatRequest{Facts: facts(d.id.Hostname), Metrics: metrics(d.n)})
		if ctx.Err() != nil {
			break
		}
		d.st.record("heartbeat", time.Since(start), err)
		if err == nil {
			if resp.HeartbeatSeconds > 0 {
				interval = time.Duration(resp.HeartbeatSeconds) * time.Second
			}
			if resp.InventoryHash != d.hash {
				start := time.Now()
				_, err := d.c.Inventory(ctx, d.inv)
				if ctx.Err() == nil {
					d.st.record("inventory", time.Since(start), err)
				}
			}
		}
		// The real agent spreads each wait by up to a tenth either way.
		sleep(ctx, interval-interval/10+time.Duration(random(float64(interval)/5)))
	}
	wg.Wait()
}

// poll keeps a job long poll open, as the real agent does.
func (d *device) poll(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		d.st.polling.Add(1)
		start := time.Now()
		// What a Linux agent's poll accepts: no job capabilities (ADR-0064);
		// the client sends the list once a server of level 2 answers.
		resp, err := d.c.Poll(ctx, []string{})
		d.st.polling.Add(-1)
		if ctx.Err() != nil {
			return
		}
		d.st.record("poll", time.Since(start), err)
		if err != nil {
			failures++
			sleep(ctx, min(5*time.Second<<min(failures-1, 6), 5*time.Minute))
			continue
		}
		failures = 0
		for _, j := range resp.Jobs {
			d.job(ctx, j)
		}
	}
}

func (d *device) job(ctx context.Context, j agentproto.SignedJob) {
	if d.jobKey == nil {
		d.st.record("job", 0, errors.New("no pinned job key"))
		return
	}
	p, err := agentproto.VerifyJob(d.jobKey, j, d.id.ID, time.Now())
	if err != nil {
		d.st.record("job", 0, err)
		return
	}
	d.st.record("delivery", time.Since(p.IssuedAt), nil)
	start := time.Now()
	sr, err := d.c.Start(ctx, p.RunID)
	d.st.record("start", time.Since(start), err)
	if err != nil || !sr.Proceed {
		return
	}
	exit := 0
	res := agentproto.ResultRequest{
		Status: agentproto.RunSucceeded, ExitCode: &exit, Stdout: "simulated on " + d.id.Hostname + "\n",
		StartedAt: start.UTC(), FinishedAt: time.Now().UTC(),
		// The program, as a Linux agent reports it: the path only.
		Interpreter: &agentproto.Interpreter{Path: "/usr/bin/" + p.Shell},
	}
	start = time.Now()
	err = d.c.Result(ctx, p.RunID, res)
	d.st.record("result", time.Since(start), err)
}

// inventory is a plausible Linux machine, the same for the same device.
func inventory(n int, host string, packages int) *agentproto.Inventory {
	inv := &agentproto.Inventory{
		System: agentproto.SystemInfo{
			Manufacturer: "QEMU", Model: "Standard PC (Q35 + ICH9, 2009)", Serial: fmt.Sprintf("SIM%07d", n),
			BIOSVendor: "SeaBIOS", BIOSVersion: "1.16.3", BIOSDate: "04/01/2014", Virtualization: "kvm",
		},
		CPU:    agentproto.CPUInfo{Model: "AMD EPYC 7763 64-Core Processor", Sockets: 1, Cores: 4, Threads: 8},
		Memory: 16 << 30,
		OS: agentproto.OSInfo{
			Name: "Ubuntu 24.04.3 LTS", ID: "ubuntu", Version: "24.04", Kernel: "6.8.0-88-generic", Timezone: "UTC",
		},
		Disks: []agentproto.Disk{{Name: "vda", Model: "QEMU HARDDISK", Serial: fmt.Sprintf("SIMDISK%05d", n), SizeBytes: 128 << 30, Kind: "ssd"}},
		Interfaces: []agentproto.Interface{{
			Name: "ens3", MAC: fmt.Sprintf("52:54:00:%02x:%02x:%02x", n>>16&0xff, n>>8&0xff, n&0xff),
			Addresses: []string{fmt.Sprintf("10.%d.%d.%d/16", 64+n>>16&0x3f, n>>8&0xff, n&0xff)}, Up: true, SpeedMbps: 10000,
		}},
		Gateways:       []string{"10.64.0.1"},
		DNS:            []string{"10.64.0.2"},
		PackageManager: "dpkg",
	}
	for i := range packages {
		inv.Packages = append(inv.Packages, agentproto.Package{
			Name: fmt.Sprintf("lib%s-sim%d", strings.Repeat("x", i%7), i), Version: fmt.Sprintf("%d.%d.%d-1ubuntu%d", i%9, i%13, i%5, i%3), Arch: "amd64",
		})
	}
	return inv
}

func metrics(n int) *agentproto.Metrics {
	return &agentproto.Metrics{
		CPUPercent: 5 + random(30), MemoryTotal: 16 << 30, MemoryUsed: 4<<30 + uint64(random(4<<30)),
		Load1: random(2), Load5: 0.8, Load15: 0.6, UptimeSeconds: int64(86400 + n), Processes: 180 + int(random(40)),
		Filesystems: []agentproto.Filesystem{
			{Mount: "/", Device: "/dev/vda1", Type: "ext4", TotalBytes: 120 << 30, UsedBytes: 40 << 30},
			{Mount: "/boot/efi", Device: "/dev/vda15", Type: "vfat", TotalBytes: 105 << 20, UsedBytes: 6 << 20},
		},
	}
}

// random is a number in [0, n), for timing jitter and made-up
// measurements.
func random(n float64) float64 {
	return mrand.Float64() * n //nolint:gosec // jitter and test data, not security
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// stats collects each request type's outcomes.
type stats struct {
	mu      sync.Mutex
	ops     map[string]*op
	polling atomic.Int64
}

type op struct {
	recent, all []time.Duration
	errs        map[string]int
	recentErrs  int
}

func newStats() *stats { return &stats{ops: map[string]*op{}} }

func (s *stats) record(name string, d time.Duration, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o := s.ops[name]
	if o == nil {
		o = &op{errs: map[string]int{}}
		s.ops[name] = o
	}
	if err != nil {
		code := client.Code(err)
		if code == "" {
			code = err.Error()
			if len(code) > 80 {
				code = code[:80]
			}
		}
		o.errs[code]++
		o.recentErrs++
		return
	}
	o.recent = append(o.recent, d)
	o.all = append(o.all, d)
}

// interval reports the requests since the last report, and starts anew.
func (s *stats) interval() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, name := range slices.Sorted(maps.Keys(s.ops)) {
		o := s.ops[name]
		p := percentiles(o.recent)
		fmt.Fprintf(&b, "  %-9s %7d ok %5d errors  p50 %8s  p95 %8s  p99 %8s  max %8s\n",
			name, len(o.recent), o.recentErrs, p[0], p[1], p[2], p[3])
		o.recent, o.recentErrs = o.recent[:0], 0
	}
	return b.String()
}

type opSummary struct {
	OK     int            `json:"ok"`
	Errors map[string]int `json:"errors"`
	P50    string         `json:"p50"`
	P95    string         `json:"p95"`
	P99    string         `json:"p99"`
	Max    string         `json:"max"`
}

type summary struct {
	Devices  int                  `json:"devices"`
	Duration string               `json:"duration"`
	Ops      map[string]opSummary `json:"ops"`
}

func (s *stats) summary(devices int, d time.Duration) summary {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := summary{Devices: devices, Duration: d.Round(time.Second).String(), Ops: map[string]opSummary{}}
	for name, o := range s.ops {
		p := percentiles(o.all)
		out.Ops[name] = opSummary{OK: len(o.all), Errors: o.errs, P50: p[0].String(), P95: p[1].String(), P99: p[2].String(), Max: p[3].String()}
	}
	return out
}

// percentiles returns p50, p95, p99 and the maximum.
func percentiles(ds []time.Duration) [4]time.Duration {
	if len(ds) == 0 {
		return [4]time.Duration{}
	}
	s := slices.Clone(ds)
	slices.Sort(s)
	at := func(q float64) time.Duration { return s[min(len(s)-1, int(q*float64(len(s))))].Round(time.Millisecond) }
	return [4]time.Duration{at(0.50), at(0.95), at(0.99), s[len(s)-1].Round(time.Millisecond)}
}
