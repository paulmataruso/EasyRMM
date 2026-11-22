package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Project is the Compose project's name, fixed by docker-compose.yml.
const Project = "easyrmm"

// Runner runs the docker command line.
type Runner interface {
	// Run runs docker with args in dir (none when ""), stdin as its
	// input, and returns its output. An error carries the end of what it
	// wrote to standard error.
	Run(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error)
}

// ExecRunner runs the docker program. Its environment is fixed: Compose
// takes variables from the environment before .env, so a variable left in
// root's shell must not change what the deployment runs.
type ExecRunner struct{}

// Run runs docker.
func (ExecRunner) Run(ctx context.Context, dir string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // arguments the updater builds
	cmd.Dir = dir
	cmd.Env = fixedEnv()
	cmd.SysProcAttr = ownGroup()
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), asKilled(ctx, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, lastLines(stderr.String(), 5)))
	}
	return stdout.Bytes(), nil
}

// fixedEnv is the environment of the commands the updater runs: a fixed
// PATH and locale, and the home directory of the user it runs as (root's,
// /root, on a host), where docker finds its configuration and, in some
// installations, its Compose plugin. Nothing else is taken from the shell.
func fixedEnv() []string {
	home := "/root"
	if u, err := currentUser(); err == nil && u.HomeDir != "" {
		home = u.HomeDir
	}
	return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=" + home, "LANG=C.UTF-8"}
}

// currentUser is the user the updater runs as; the tests' is another.
var currentUser = user.Current

// ownGroup puts a command in a process group of its own: a terminal's
// Ctrl-C or hang-up, which reaches its foreground group, must not stop
// Compose halfway through an upgrade. The updater itself ignores them while
// an attempt runs.
func ownGroup() *syscall.SysProcAttr { return &syscall.SysProcAttr{Setpgid: true} }

// lastLines is the end of a command's error output, on one line.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " / ")
}

// Docker is what the updater asks of Docker and Compose.
type Docker struct{ R Runner }

// CheckDaemon refuses Docker's user namespace remapping and rootless
// Docker, under which the deployment's ownership is wrong anyway.
func (d Docker) CheckDaemon(ctx context.Context) error {
	out, err := d.R.Run(ctx, "", nil, "info", "--format", "{{json .SecurityOptions}}")
	if err != nil {
		return err
	}
	var opts []string
	if err := json.Unmarshal(bytes.TrimSpace(out), &opts); err != nil {
		return fmt.Errorf("docker info: %w", err)
	}
	for _, o := range opts {
		for _, f := range strings.Split(o, ",") {
			switch f {
			case "name=userns":
				return fmt.Errorf("Docker remaps user namespaces (userns-remap): the deployment's ownership is wrong under it, and the updater does not run there")
			case "name=rootless":
				return fmt.Errorf("Docker runs rootless: the deployment's ownership is wrong under it, and the updater does not run there")
			}
		}
	}
	return nil
}

// RootDir is Docker's data directory, where pulled images go.
func (d Docker) RootDir(ctx context.Context) (string, error) {
	out, err := d.R.Run(ctx, "", nil, "info", "--format", "{{.DockerRootDir}}")
	return strings.TrimSpace(string(out)), err
}

// Images lists the images the deployment in dir runs, with its profiles:
// `docker compose config --images`, sorted, each once.
func (d Docker) Images(ctx context.Context, dir string) ([]string, error) {
	return d.lines(ctx, dir, "compose", "config", "--images")
}

func (d Docker) lines(ctx context.Context, dir string, args ...string) ([]string, error) {
	out, err := d.R.Run(ctx, dir, nil, args...)
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	slices.Sort(lines)
	return slices.Compact(lines), nil
}

// Pull pulls the deployment's images.
func (d Docker) Pull(ctx context.Context, dir string) error {
	_, err := d.R.Run(ctx, dir, nil, "compose", "pull", "--quiet")
	return err
}

// HasImage reports whether an image is in Docker's store.
func (d Docker) HasImage(ctx context.Context, ref string) bool {
	_, err := d.R.Run(ctx, "", nil, "image", "inspect", "--format", "{{.Id}}", ref)
	return err == nil
}

// Stop stops the deployment's services in the order Compose stops them,
// PostgreSQL last since everything depends on it, then any of the
// project's containers still running.
func (d Docker) Stop(ctx context.Context, dir string) error {
	if _, err := d.R.Run(ctx, dir, nil, "compose", "stop"); err != nil {
		return err
	}
	ids, err := d.lines(ctx, "", "ps", "-q", "--filter", "label=com.docker.compose.project="+Project)
	if err != nil || len(ids) == 0 {
		return err
	}
	if _, err := d.R.Run(ctx, "", nil, append([]string{"stop"}, ids...)...); err != nil {
		return err
	}
	ids, err = d.lines(ctx, "", "ps", "-q", "--filter", "label=com.docker.compose.project="+Project)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		return fmt.Errorf("containers of %s still run after stopping: %s", Project, strings.Join(ids, " "))
	}
	return nil
}

// RunningFrom lists the project directories (deploy/) the project's running
// containers were started from.
func (d Docker) RunningFrom(ctx context.Context) ([]string, error) {
	return d.lines(ctx, "", "ps", "--filter", "label=com.docker.compose.project="+Project, "--format", `{{.Label "com.docker.compose.project.working_dir"}}`)
}

// Up starts the services named, with the one-shot services they depend
// on, and waits until each runs, healthy where it has a health check, or
// the timeout passes.
func (d Docker) Up(ctx context.Context, dir string, timeout time.Duration, services ...string) error {
	args := append([]string{"compose", "up", "--detach", "--remove-orphans", "--wait", "--wait-timeout", strconv.Itoa(int(timeout.Seconds()))}, services...)
	_, err := d.R.Run(ctx, dir, nil, args...)
	return err
}

// plan sorts the deployment's services, with its profiles: those that keep
// running, and the one-shot services (restart: "no") that no service
// depends on, such as authentik-setup. Compose's --wait fails when a
// service it waits for exits, even successfully, unless another service
// waits for it to complete; so those run on their own.
func (d Docker) plan(ctx context.Context, dir string) (running, leaves []string, err error) {
	out, err := d.R.Run(ctx, dir, nil, "compose", "config", "--format", "json")
	if err != nil {
		return nil, nil, err
	}
	var cfg struct {
		Services map[string]struct {
			Restart   string                     `json:"restart"`
			DependsOn map[string]json.RawMessage `json:"depends_on"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, nil, fmt.Errorf("docker compose config: %w", err)
	}
	needed := map[string]bool{}
	for _, s := range cfg.Services {
		for dep := range s.DependsOn {
			needed[dep] = true
		}
	}
	for name, s := range cfg.Services {
		switch {
		case s.Restart != "no":
			running = append(running, name)
		case !needed[name]:
			leaves = append(leaves, name)
		}
	}
	if len(running) == 0 {
		return nil, nil, fmt.Errorf("docker compose config lists no service that keeps running")
	}
	slices.Sort(running)
	slices.Sort(leaves)
	return running, leaves, nil
}

// Where Compose mounts the updater's status directory, and the operator's
// certificates, into the server.
const (
	statusMount = "/run/easyrmm-updater"
	tlsMount    = "/etc/easyrmm/tls"
)

// composeMount is one of a service's volumes, as docker compose config
// lists it.
type composeMount struct {
	Service  string `json:"-"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// Mounts lists the volumes of the deployment in dir, with its profiles,
// by service and target.
func (d Docker) Mounts(ctx context.Context, dir string) ([]composeMount, error) {
	out, err := d.R.Run(ctx, dir, nil, "compose", "config", "--format", "json")
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Services map[string]struct {
			Volumes []composeMount `json:"volumes"`
		} `json:"services"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return nil, fmt.Errorf("docker compose config: %w", err)
	}
	var mounts []composeMount
	for name, s := range cfg.Services {
		for _, m := range s.Volumes {
			m.Service = name
			mounts = append(mounts, m)
		}
	}
	slices.SortFunc(mounts, func(a, b composeMount) int {
		return strings.Compare(a.Service+" "+a.Target, b.Service+" "+b.Target)
	})
	return mounts, nil
}

// dataRootOf is the data root Compose reads for the deployment in dir:
// the directory above the updater's status directory, <data root>/updater/
// status, which it mounts into the server.
func dataRootOf(mounts []composeMount, dir string) (string, error) {
	for _, m := range mounts {
		if m.Service != "server" || m.Target != statusMount {
			continue
		}
		root, ok := strings.CutSuffix(m.Source, "/updater/status")
		if !ok {
			return "", fmt.Errorf("the server's %s is mounted from %s, not from the data root's updater/status", statusMount, m.Source)
		}
		return root, nil
	}
	return "", fmt.Errorf("the deployment in %s does not mount the updater's status directory into the server: set it up again with its setup.sh", dir)
}

// systemPaths are the host's files a service may mount from outside the
// data root and the deployment: they hold none of its state.
var systemPaths = []string{"/etc/localtime", "/etc/timezone", "/run/docker.sock", "/var/run/docker.sock"}

// checkMounts refuses a deployment, in deployDir, that mounts what a backup
// does not hold, and so a rollback would not restore. Each volume must be a
// tmpfs, or a bind mount from:
//   - the data root, but for the entries backups leave out (the updater's
//     own status directory, which it writes itself, aside);
//   - the deployment's own tree, deploy/ and docker/ beside it, which a
//     backup copies;
//   - anywhere, read-only, for the server's certificates (EASYRMM_TLS_DIR
//     in manual TLS mode: the operator's, which no upgrade changes);
//   - one of the system paths.
func checkMounts(mounts []composeMount, dataRoot, deployDir string) error {
	trees := resolved(filepath.Dir(deployDir))
	inTree := func(src string) bool {
		for _, t := range trees {
			if inDir(src, filepath.Join(t, "deploy")) || inDir(src, filepath.Join(t, "docker")) {
				return true
			}
		}
		return false
	}
	for _, m := range mounts {
		src := filepath.Clean(m.Source)
		rel, _ := filepath.Rel(dataRoot, src)
		switch {
		case m.Type == "tmpfs":
		case m.Type != "bind":
			return fmt.Errorf("the service %s mounts a %s volume at %s: a backup holds the data root and the deployment's directory only, and a rollback would not restore it", m.Service, m.Type, m.Target)
		case inDir(src, dataRoot) && rel != "." && !skippedEntry(strings.SplitN(rel, "/", 2)[0]):
		case src == string(statusDirOf(dataRoot)) && m.Target == statusMount && m.ReadOnly:
		case inTree(src):
		case m.Service == "server" && m.Target == tlsMount && m.ReadOnly:
		case slices.Contains(systemPaths, src):
		default:
			return fmt.Errorf("the service %s mounts %s at %s, outside the data root %s and the deployment's directory %s: a backup would not hold it, and a rollback would not restore it. Move it into the data root (docs/operations/updater.md#the-data-root)", m.Service, src, m.Target, dataRoot, filepath.Dir(deployDir))
		}
	}
	return nil
}

// inDir reports whether path is dir or lies under it, by their names.
func inDir(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}

// composeFiles are the files Compose reads in a project directory with
// docker-compose.yml, or instead of it.
var composeFiles = []string{
	"compose.yaml", "compose.yml", "docker-compose.yaml",
	"compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml",
}

// checkComposeFiles refuses a deployment directory with another file
// Compose would read: the updater backs up, restores and starts the
// deployment as docker-compose.yml says.
func checkComposeFiles(dir string) error {
	for _, name := range composeFiles {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			return fmt.Errorf("%s is in %s: Compose reads it with docker-compose.yml, or instead of it, and the updater backs up, restores and starts the deployment as docker-compose.yml alone says. Move what it changes into docker-compose.yml's settings in .env, or remove it", name, dir)
		}
	}
	return nil
}

// Start starts the deployment's services but those excluded, within the
// timeout: those that keep running, each running and healthy where it has
// a health check (the one-shot services they depend on run first, to
// completion), then the one-shot services nothing depends on, each run to
// a successful end.
func (d Docker) Start(ctx context.Context, dir string, timeout time.Duration, exclude ...string) error {
	running, leaves, err := d.plan(ctx, dir)
	if err != nil {
		return err
	}
	keep := func(s string) bool { return slices.Contains(exclude, s) }
	if err := d.Up(ctx, dir, timeout, slices.DeleteFunc(running, keep)...); err != nil {
		return err
	}
	leaves = slices.DeleteFunc(leaves, keep)
	if len(leaves) == 0 {
		return nil
	}
	if _, err := d.R.Run(ctx, dir, nil, append([]string{"compose", "up", "--detach", "--no-deps"}, leaves...)...); err != nil {
		return err
	}
	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := d.R.Run(wctx, dir, nil, append([]string{"compose", "wait"}, leaves...)...); err != nil {
		return fmt.Errorf("the one-shot services %v: %w", leaves, err)
	}
	return nil
}

// Exec runs a command in a running service, as user when not "".
func (d Docker) Exec(ctx context.Context, dir string, stdin []byte, user, service string, command ...string) ([]byte, error) {
	args := []string{"compose", "exec", "-T"}
	if user != "" {
		args = append(args, "--user", user)
	}
	args = append(append(args, service), command...)
	return d.R.Run(ctx, dir, stdin, args...)
}

// ServerVersion is what the running server says its version is.
func (d Docker) ServerVersion(ctx context.Context, dir string) (string, error) {
	out, err := d.Exec(ctx, dir, nil, "", "server", "easyrmm-server", "version")
	return strings.TrimSpace(string(out)), err
}

// serverReady checks the started server on the host's loopback, never
// through its public edge: its readiness (easyrmm-server healthcheck asks
// /readyz on its loopback health port, which passes while it is held) and
// its version.
func (d Docker) serverReady(ctx context.Context, dir, version string) error {
	if out, err := d.Exec(ctx, dir, nil, "", "server", "easyrmm-server", "healthcheck"); err != nil {
		return fmt.Errorf("the started server is not ready: %w: %s", err, lastLines(string(out), 3))
	}
	v, err := d.ServerVersion(ctx, dir)
	if err != nil {
		return fmt.Errorf("asking the started server its version: %w", err)
	}
	if v != version {
		return fmt.Errorf("the started server reports %q, not %s", v, version)
	}
	return nil
}

// Psql runs SQL as PostgreSQL's superuser over the container's local
// socket, in one transaction, with vars set as psql variables (:'name' in
// the SQL quotes one), and returns its unaligned output.
func (d Docker) Psql(ctx context.Context, dir, sql string, vars map[string]string) (string, error) {
	cmd := []string{"psql", "-X", "-q", "-A", "-t", "-1", "-v", "ON_ERROR_STOP=1", "-p", "15432", "-d", "easyrmm"}
	keys := make([]string, 0, len(vars))
	for k := range vars {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		cmd = append(cmd, "-v", k+"="+vars[k])
	}
	cmd = append(cmd, "-f", "-")
	out, err := d.Exec(ctx, dir, []byte(sql), "postgres", "postgres", cmd...)
	return strings.TrimSpace(string(out)), err
}
