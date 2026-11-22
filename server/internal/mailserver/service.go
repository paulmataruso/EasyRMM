// Package mailserver is EasyRMM's mail server (ADR-0053, slice 1): the one
// set in the console by super administrators, or EASYRMM_SMTP_* in .env,
// which wins; the limits on the mail sent through it, account mail first;
// its test message; and account mail (invitations, password resets).
package mailserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/secrets"
)

// Where the mail server in force comes from.
const (
	FromEnv     = "env"
	FromConsole = "console"
	FromNowhere = "none"
)

// How EasyRMM signs in to the mail server.
const (
	SignInNone     = "none"
	SignInPassword = "password"
)

// TestInterval is how often a test message may be sent.
const TestInterval = 30 * time.Second

// passwordAD binds the sealed password to its column.
var passwordAD = []byte("mail_server.password")

var (
	// ErrFromEnv is a change to the console's mail server while .env's is in
	// force.
	ErrFromEnv = apperr.Conflict("mail_server_from_env",
		"The mail server comes from EASYRMM_SMTP_HOST in .env, which wins over the console. Remove it from .env and restart EasyRMM to set the mail server here.")
	// ErrNoMailServer is mail to send with no mail server in force.
	ErrNoMailServer = apperr.Conflict("no_mail_server", "EasyRMM has no mail server. Set one under Settings → Notifications → Mail server.")
)

// TooSoonError is a test message asked for less than TestInterval after the
// last one.
type TooSoonError struct{ RetryAfter time.Duration }

func (e *TooSoonError) Error() string {
	return fmt.Sprintf("A test message went less than %d seconds ago. Try again in %d seconds.", int(TestInterval.Seconds()), e.Seconds())
}

// Seconds is how long to wait, in whole seconds, at least one.
func (e *TooSoonError) Seconds() int { return seconds(e.RetryAfter) }

// Service keeps the mail server's settings and sends through it.
type Service struct {
	db     *database.DB
	audit  *audit.Logger
	sealer *secrets.Sealer
	// env is .env's mail server, nil when EASYRMM_SMTP_HOST is not set.
	env *mailer.Config
	log *slog.Logger

	// available caches Available for availableFor, so that the sign-in
	// page and reset requests, which anyone may send, seldom reach the
	// database; a change on this server clears it, and changes counts the
	// changes, so that an answer read before one is not kept after it.
	availableMu sync.Mutex
	availableAt time.Time
	available   bool
	changes     int

	onChange []func()
}

// availableFor is how long Available's answer is kept. A change made on
// another server is seen within it.
const availableFor = 5 * time.Second

// New builds the service. env is .env's mail server, or nil; it is checked
// here, so that the server does not start with a mail server it cannot use.
func New(db *database.DB, auditLog *audit.Logger, sealer *secrets.Sealer, env *mailer.Config, log *slog.Logger) (*Service, error) {
	if env != nil {
		if _, err := mailer.New(*env); err != nil {
			return nil, fmt.Errorf("EASYRMM_SMTP_*: %w", err)
		}
	}
	return &Service{db: db, audit: auditLog, sealer: sealer, env: env, log: log}, nil
}

// OnChange registers f, called after every change of the console's mail
// server. It must not block.
func (s *Service) OnChange(f func()) { s.onChange = append(s.onChange, f) }

func (s *Service) changed() {
	s.availableMu.Lock()
	s.availableAt = time.Time{}
	s.changes++
	s.availableMu.Unlock()
	for _, f := range s.onChange {
		f()
	}
}

// Server is a mail server as the console shows it. The password is never
// shown.
type Server struct {
	Host        string     `json:"host"`
	Port        int        `json:"port"`
	Security    string     `json:"security"`
	SignIn      string     `json:"signIn"`
	Username    string     `json:"username"`
	PasswordSet bool       `json:"passwordSet"`
	FromAddress string     `json:"fromAddress"`
	FromName    string     `json:"fromName"`
	UpdatedAt   *time.Time `json:"updatedAt,omitempty"`
	UpdatedBy   string     `json:"updatedBy,omitempty"`
}

// Limits are the messages a minute and a day sent through the mail server
// in force, and the fixed limits on administrators' account mail.
type Limits struct {
	PerMinute int        `json:"perMinute"`
	PerDay    int        `json:"perDay"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	UpdatedBy string     `json:"updatedBy,omitempty"`
	// AdminPerHour and OrganizationPerDay are AdminPerHour and
	// OrganizationPerDay, for the console to show.
	AdminPerHour       int `json:"adminPerHour"`
	OrganizationPerDay int `json:"organizationPerDay"`
}

// Usage is the messages sent in the last minute and the last 24 hours, and
// of those how many were account mail.
type Usage struct {
	LastMinute     int `json:"lastMinute"`
	LastDay        int `json:"lastDay"`
	AccountLastDay int `json:"accountLastDay"`
	// AdminDayLimit is where administrators' invitations and password links
	// stop, 90% of the day's limit; OtherDayLimit where other mail stops,
	// 80%. Password resets people ask for may use the whole day.
	AdminDayLimit int `json:"adminDayLimit"`
	OtherDayLimit int `json:"otherDayLimit"`
}

// View is the mail server settings and their state.
type View struct {
	// InForce is where the mail server in force comes from: env, console
	// or none.
	InForce string `json:"inForce"`
	// Env is .env's mail server, read-only; Console the console's, when set.
	Env     *Server `json:"env,omitempty"`
	Console *Server `json:"console,omitempty"`
	Limits  Limits  `json:"limits"`
	Usage   Usage   `json:"usage"`
}

// row is the stored settings.
type row struct {
	host, security, signIn, username, sealed, fromAddress, fromName string
	port, perMinute, perDay                                         int
	updatedAt, limitsUpdatedAt                                      *time.Time
	updatedBy, limitsUpdatedBy                                      *string
}

func loadRow(ctx context.Context, tx pgx.Tx, lock bool) (*row, error) {
	q := `SELECT m.host, m.port, m.security, m.sign_in, m.username, m.password_sealed, m.from_address, m.from_name,
		m.per_minute, m.per_day, m.updated_at, u.email, m.limits_updated_at, l.email
		FROM mail_server m LEFT JOIN users u ON u.id = m.updated_by LEFT JOIN users l ON l.id = m.limits_updated_by`
	if lock {
		q += ` FOR UPDATE OF m`
	}
	var r row
	err := tx.QueryRow(ctx, q).Scan(&r.host, &r.port, &r.security, &r.signIn, &r.username, &r.sealed, &r.fromAddress, &r.fromName,
		&r.perMinute, &r.perDay, &r.updatedAt, &r.updatedBy, &r.limitsUpdatedAt, &r.limitsUpdatedBy)
	return &r, err
}

// config is the console's mail server as the mailer takes it, nil when none
// is set.
func (r *row) config(sealer *secrets.Sealer) (*mailer.Config, error) {
	if r.host == "" {
		return nil, nil
	}
	cfg := &mailer.Config{Host: r.host, Port: r.port, Security: r.security, FromAddress: r.fromAddress, FromName: r.fromName}
	if r.signIn == SignInPassword {
		pw, err := sealer.Open(r.sealed, passwordAD)
		if err != nil {
			return nil, errors.New("the mail server's stored password cannot be opened with this server's secret key; enter it again under Settings → Notifications → Mail server")
		}
		cfg.Username, cfg.Password = r.username, string(pw)
	}
	return cfg, nil
}

func (r *row) server() *Server {
	if r.host == "" {
		return nil
	}
	sv := &Server{Host: r.host, Port: r.port, Security: r.security, SignIn: r.signIn, Username: r.username, PasswordSet: r.sealed != "",
		FromAddress: r.fromAddress, FromName: r.fromName, UpdatedAt: r.updatedAt}
	if r.updatedBy != nil {
		sv.UpdatedBy = *r.updatedBy
	}
	return sv
}

func envServer(c *mailer.Config) *Server {
	signIn := SignInNone
	if c.Username != "" {
		signIn = SignInPassword
	}
	return &Server{Host: c.Host, Port: c.Port, Security: c.Security, SignIn: signIn, Username: c.Username, PasswordSet: c.Password != "",
		FromAddress: c.FromAddress, FromName: c.FromName}
}

// Get returns the settings, which mail server is in force, and the usage.
func (s *Service) Get(ctx context.Context) (View, error) {
	var v View
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := loadRow(ctx, tx, false)
		if err != nil {
			return err
		}
		v.Console = r.server()
		v.Limits = Limits{PerMinute: r.perMinute, PerDay: r.perDay, UpdatedAt: r.limitsUpdatedAt, AdminPerHour: AdminPerHour,
			OrganizationPerDay: OrganizationPerDay}
		if r.limitsUpdatedBy != nil {
			v.Limits.UpdatedBy = *r.limitsUpdatedBy
		}
		v.Usage, err = usage(ctx, tx, r.perDay)
		return err
	})
	switch {
	case s.env != nil:
		v.InForce, v.Env = FromEnv, envServer(s.env)
	case v.Console != nil:
		v.InForce = FromConsole
	default:
		v.InForce = FromNowhere
	}
	return v, err
}

// InForce is the mail server in force: .env's when set, else the
// console's; nil when there is none.
func (s *Service) InForce(ctx context.Context) (*mailer.Config, error) {
	if s.env != nil {
		c := *s.env
		return &c, nil
	}
	var cfg *mailer.Config
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		r, err := loadRow(ctx, tx, false)
		if err != nil {
			return err
		}
		cfg, err = r.config(s.sealer)
		return err
	})
	return cfg, err
}

// Available reports whether a mail server is in force, for password reset
// to offer itself, as read within availableFor. A failure to read the
// settings is logged and reads as none, and is not kept.
func (s *Service) Available(ctx context.Context) bool {
	if s.env != nil {
		return true
	}
	s.availableMu.Lock()
	if !s.availableAt.IsZero() && time.Since(s.availableAt) < availableFor {
		defer s.availableMu.Unlock()
		return s.available
	}
	changes := s.changes
	s.availableMu.Unlock()
	var host string
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT host FROM mail_server`).Scan(&host)
	})
	if err != nil {
		if ctx.Err() == nil {
			s.log.Error("mail server: reading the settings", "error", err)
		}
		return false
	}
	s.availableMu.Lock()
	if s.changes == changes {
		s.availableAt, s.available = time.Now(), host != ""
	}
	s.availableMu.Unlock()
	return host != ""
}

// Input is the console's mail server, to save or to test.
type Input struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"`
	SignIn   string `json:"signIn"`
	Username string `json:"username"`
	// Password is write-only. Left empty, the stored one is kept while the
	// host, the port, the security and the user name stay the same: a
	// stored password never goes to a server, or over a connection, it was
	// not entered for.
	Password    string `json:"password"`
	FromAddress string `json:"fromAddress"`
	FromName    string `json:"fromName"`
}

var hostLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// validHost accepts an IP address, without a zone, or a DNS name.
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == ""
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// The longest password and sender's name, in UTF-16 code units, as the
// patching engine, which gets them too, counts characters.
const (
	maxPassword = 512
	maxFromName = 100
)

// utf16Len is the length of s in UTF-16 code units.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// keepsPassword reports whether in may keep stored's password: it signs in
// to the same host, on the same port, with the same security, as the same
// user.
func keepsPassword(in *Input, stored *row) bool {
	return stored != nil && stored.signIn == SignInPassword && strings.EqualFold(stored.host, in.Host) && stored.port == in.Port &&
		stored.security == in.Security && stored.username == in.Username
}

// check validates in, cleaning it, and works out the mailer's configuration,
// using the stored password when in gives none and keepsPassword allows.
func (s *Service) check(in *Input, stored *row) (mailer.Config, error) {
	f := apperr.Fields{}
	in.Host = strings.TrimSpace(in.Host)
	if strings.HasPrefix(in.Host, "[") && strings.HasSuffix(in.Host, "]") {
		in.Host = in.Host[1 : len(in.Host)-1]
	}
	in.Username, in.FromAddress, in.FromName = strings.TrimSpace(in.Username), strings.TrimSpace(in.FromAddress), strings.TrimSpace(in.FromName)
	switch {
	case in.Host == "":
		f.Add("host", "Enter the mail server's host name or IP address.")
	case !validHost(in.Host):
		f.Add("host", "Enter a host name or an IP address, without a scheme or a port.")
	}
	f.Check(in.Port >= 1 && in.Port <= 65535, "port", "Enter a port from 1 to 65535.")
	switch in.Security {
	case mailer.StartTLS, mailer.TLS:
	case mailer.None:
		f.Check(in.Host == "" || mailer.Loopback(in.Host), "security", "Without encryption, EasyRMM sends only to a relay on this machine (localhost or a loopback address).")
	default:
		f.Add("security", "Choose STARTTLS, TLS or none.")
	}
	cfg := mailer.Config{Host: in.Host, Port: in.Port, Security: in.Security, FromAddress: in.FromAddress, FromName: in.FromName}
	switch in.SignIn {
	case SignInNone:
		f.Check(in.Username == "" && in.Password == "", "username", "A user name and password are used only when signing in with a password.")
	case SignInPassword:
		switch {
		case in.Username == "":
			f.Add("username", "Enter the user name to sign in with.")
		case len(in.Username) > 255 || strings.ContainsFunc(in.Username, unicode.IsControl):
			f.Add("username", "Enter a user name of at most 255 characters, on one line.")
		}
		switch {
		case in.Password != "":
			f.Check(utf16Len(in.Password) <= maxPassword && !strings.ContainsAny(in.Password, "\x00\r\n"), "password",
				"Enter a password of at most 512 characters, on one line.")
			cfg.Username, cfg.Password = in.Username, in.Password
		case keepsPassword(in, stored):
			pw, err := s.sealer.Open(stored.sealed, passwordAD)
			if err != nil {
				f.Add("password", "The stored password cannot be opened with this server's secret key. Enter it again.")
			}
			cfg.Username, cfg.Password = in.Username, string(pw)
		default:
			f.Add("password", "Enter the password. A stored password is kept only while the server, the port, the security and the user name stay the same.")
		}
	default:
		f.Add("signIn", "Choose to sign in with a password, or not at all.")
	}
	switch {
	case in.FromAddress == "":
		f.Add("fromAddress", "Enter the address EasyRMM sends from.")
	case !mailer.BareAddress(in.FromAddress):
		f.Add("fromAddress", "Enter one email address, such as rmm@example.com, without a name.")
	}
	f.Check(utf16Len(in.FromName) <= maxFromName && !strings.ContainsFunc(in.FromName, unicode.IsControl), "fromName",
		"Enter a name of at most 100 characters, on one line.")
	return cfg, f.Err()
}

func actorID(a audit.Actor) *uuid.UUID {
	if a.Type == audit.ActorUser && a.ID != uuid.Nil {
		return &a.ID
	}
	return nil
}

// Update saves the console's mail server, which is in force at once unless
// .env's is.
func (s *Service) Update(ctx context.Context, actor audit.Actor, in Input) (View, error) {
	if s.env != nil {
		return View{}, ErrFromEnv
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		stored, err := loadRow(ctx, tx, true)
		if err != nil {
			return err
		}
		cfg, err := s.check(&in, stored)
		if err != nil {
			return err
		}
		sealed := ""
		if in.SignIn == SignInPassword {
			if sealed, err = s.sealer.Seal([]byte(cfg.Password), passwordAD); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE mail_server SET host = $1, port = $2, security = $3, sign_in = $4, username = $5,
			password_sealed = $6, from_address = $7, from_name = $8, updated_at = now(), updated_by = $9`,
			in.Host, in.Port, in.Security, in.SignIn, in.Username, sealed, in.FromAddress, in.FromName, actorID(actor)); err != nil {
			return err
		}
		// From and to, as for the limits; never the password, only whether
		// it changed: a new one, or the stored one removed.
		change := func(from, to any) map[string]any { return map[string]any{"from": from, "to": to} }
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "mail_server.update", Outcome: audit.Success,
			TargetType: "mail_server", TargetID: net.JoinHostPort(in.Host, strconv.Itoa(in.Port)),
			Details: map[string]any{"host": change(stored.host, in.Host), "port": change(stored.port, in.Port),
				"security": change(stored.security, in.Security), "signIn": change(stored.signIn, in.SignIn),
				"username": change(stored.username, in.Username), "fromAddress": change(stored.fromAddress, in.FromAddress),
				"fromName":        change(stored.fromName, in.FromName),
				"passwordChanged": in.Password != "" || (stored.sealed != "" && sealed == "")}})
	})
	if err != nil {
		return View{}, err
	}
	s.changed()
	return s.Get(ctx)
}

// Delete removes the console's mail server and its stored password; the
// limits stay. While .env's mail server is in force it may still be
// removed, which changes nothing that is sent.
func (s *Service) Delete(ctx context.Context, actor audit.Actor) (View, error) {
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		stored, err := loadRow(ctx, tx, true)
		if err != nil {
			return err
		}
		if stored.host == "" {
			return apperr.NotFound()
		}
		if _, err := tx.Exec(ctx, `UPDATE mail_server SET host = '', port = 587, security = 'starttls', sign_in = 'none', username = '',
			password_sealed = '', from_address = '', from_name = '', updated_at = now(), updated_by = $1`, actorID(actor)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "mail_server.delete", Outcome: audit.Success,
			TargetType: "mail_server", TargetID: net.JoinHostPort(stored.host, strconv.Itoa(stored.port)),
			Details: map[string]any{"host": stored.host, "port": stored.port, "inForce": s.env == nil}})
	})
	if err != nil {
		return View{}, err
	}
	s.changed()
	return s.Get(ctx)
}

// LimitsInput is a change of the limits.
type LimitsInput struct {
	PerMinute int `json:"perMinute"`
	PerDay    int `json:"perDay"`
}

// SetLimits changes the limits, whichever mail server is in force.
func (s *Service) SetLimits(ctx context.Context, actor audit.Actor, in LimitsInput) (View, error) {
	f := apperr.Fields{}
	f.Check(in.PerMinute >= 1 && in.PerMinute <= 10_000, "perMinute", "Enter from 1 to 10,000 messages a minute.")
	f.Check(in.PerDay >= 1 && in.PerDay <= 1_000_000, "perDay", "Enter from 1 to 1,000,000 messages a day.")
	if len(f) == 0 {
		f.Check(in.PerDay >= in.PerMinute, "perDay", "Allow at least as many messages a day as a minute.")
	}
	if err := f.Err(); err != nil {
		return View{}, err
	}
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		stored, err := loadRow(ctx, tx, true)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE mail_server SET per_minute = $1, per_day = $2, limits_updated_at = now(), limits_updated_by = $3`,
			in.PerMinute, in.PerDay, actorID(actor)); err != nil {
			return err
		}
		return s.audit.Write(ctx, tx, audit.Event{Actor: actor, Action: "mail_server.limits_update", Outcome: audit.Success,
			TargetType: "mail_server", TargetID: "limits", Details: map[string]any{
				"perMinute": map[string]any{"from": stored.perMinute, "to": in.PerMinute},
				"perDay":    map[string]any{"from": stored.perDay, "to": in.PerDay}}})
	})
	if err != nil {
		return View{}, err
	}
	return s.Get(ctx)
}

func seconds(d time.Duration) int {
	n := int((d + time.Second - 1) / time.Second)
	return max(n, 1)
}
