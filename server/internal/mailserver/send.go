package mailserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
)

// lockMail serializes taking room under the limits, across servers.
const lockMail = 4471209853361

// accountWait is the longest account mail waits for room under the
// minute's limit.
const accountWait = 65 * time.Second

// Limits on the invitations and password links administrators email,
// decided in review of #82 (ADR-0053), so that no administrator or
// organization can use up the platform's mail:
//
//   - AdminPerHour: one a minute, kept up for an hour, is more than anyone
//     inviting a team or sending links by hand needs, and stops a script or
//     a stolen session at 1,440 a day.
//   - OrganizationPerDay: enough to bring a customer of several hundred
//     people on in a day, and under 6% of the default 9,000 a day.
const (
	AdminPerHour       = 60
	OrganizationPerDay = 500
)

// kind is what a message counts as. A password reset the person asked for
// may use the whole day's limit; an administrator's invitation or password
// link stops at 90% of it, so that the rest is kept for resets whatever
// administrators send; other mail stops at 80%, so that account mail goes
// first.
type kind string

const (
	kindReset kind = "reset"
	kindAdmin kind = "admin"
	kindOther kind = "other"
)

// dayLimit is how much of the day's limit k may use.
func (k kind) dayLimit(perDay int) int {
	switch k {
	case kindReset:
		return perDay
	case kindAdmin:
		return perDay * 9 / 10
	default:
		return perDay * 8 / 10
	}
}

// charge is whom a message counts against.
type charge struct {
	kind kind
	// admin and organization, for kindAdmin: nil for none.
	admin, organization *uuid.UUID
}

func accountCharge(by mailer.AccountMail) charge {
	if by.Self {
		return charge{kind: kindReset}
	}
	ch := charge{kind: kindAdmin}
	if by.Admin != uuid.Nil {
		ch.admin = &by.Admin
	}
	if by.Organization != uuid.Nil {
		ch.organization = &by.Organization
	}
	return ch
}

// LimitError is a message the limits did not let go.
type LimitError struct {
	// Day is the day's limit reached, or the share of it this mail may use;
	// otherwise the minute's.
	Day bool
	// Kind is reset, admin or other (see kind).
	Kind string
	// AccountWaiting is other mail standing back for account mail.
	AccountWaiting bool
	// Admin is the administrator's own limit reached, AdminPerHour;
	// Organization the organization's, OrganizationPerDay.
	Admin        bool
	Organization bool
	PerMinute    int
	PerDay       int
	RetryAfter   time.Duration
}

func (e *LimitError) Error() string {
	switch {
	case e.Admin:
		return fmt.Sprintf("You have emailed %d invitations and password links in the last hour, the most one administrator may. Try again in %s.",
			AdminPerHour, waitWords(e.RetryAfter))
	case e.Organization:
		return fmt.Sprintf("This organization's accounts have been emailed %d invitations and password links in the last 24 hours, the most one organization may. Try again in %s.",
			OrganizationPerDay, waitWords(e.RetryAfter))
	case e.Day && e.Kind == string(kindReset):
		return fmt.Sprintf("Not sent: the limit of %s messages a day is reached. Raise it under Settings → Notifications → Mail server, or wait until the oldest of them is 24 hours old.",
			thousands(e.PerDay))
	case e.Day && e.Kind == string(kindAdmin):
		return fmt.Sprintf("Not sent: messages in the last 24 hours reach %s, 90%% of the limit of %s a day; the rest is kept for password resets people ask for.",
			thousands(kindAdmin.dayLimit(e.PerDay)), thousands(e.PerDay))
	case e.Day:
		return fmt.Sprintf("Not sent: messages in the last 24 hours reach %s, 80%% of the limit of %s a day; the rest is kept for invitations and password resets.",
			thousands(kindOther.dayLimit(e.PerDay)), thousands(e.PerDay))
	case e.AccountWaiting:
		return fmt.Sprintf("Not sent: invitations or password resets are waiting for room under the limit of %s messages a minute, and go first. Try again in a minute.",
			thousands(e.PerMinute))
	default:
		return fmt.Sprintf("Not sent: the limit of %s messages a minute is reached. Try again in %d seconds.", thousands(e.PerMinute), seconds(e.RetryAfter))
	}
}

// gate counts each message against the limits.
func (s *Service) gate(ch charge) mailer.Gate {
	return func(ctx context.Context) (func(), error) {
		id, err := s.take(ctx, ch)
		if err != nil {
			return nil, err
		}
		return func() { s.untake(id) }, nil
	}
}

// take makes room for one message under the limits and counts it. Account
// mail waits up to accountWait for room under the minute's limit, and
// other mail on every server stands back meanwhile; other mail does not
// wait.
func (s *Service) take(ctx context.Context, ch charge) (int64, error) {
	until := time.Now().Add(accountWait)
	var waiting int64
	defer func() {
		if waiting != 0 {
			s.unwait(waiting)
		}
	}()
	for {
		id, refused, err := s.tryTake(ctx, ch)
		switch {
		case err != nil:
			return 0, err
		case refused == nil:
			return id, nil
		case refused.Day || refused.Admin || refused.Organization || ch.kind == kindOther || time.Now().Add(refused.RetryAfter).After(until):
			return 0, refused
		}
		if waiting == 0 {
			if waiting, err = s.wait(ctx, time.Until(until)); err != nil {
				return 0, err
			}
		}
		t := time.NewTimer(max(refused.RetryAfter, 50*time.Millisecond))
		select {
		case <-ctx.Done():
			t.Stop()
			return 0, ctx.Err()
		case <-t.C:
		}
	}
}

// counts is what the limits count for one message.
type counts struct {
	perMinute, perDay int
	minute, day       int
	// minuteWait is how long until the minute has room, in seconds.
	minuteWait float64
	// admin and organization count the administrator's account mail in
	// the last hour, and the organization's in the last 24 hours, with how
	// long until each has room.
	admin, organization         int
	adminWait, organizationWait float64
	// waiting: account mail is waiting for room, on some server.
	waiting bool
}

func readCounts(ctx context.Context, tx pgx.Tx, ch charge) (counts, error) {
	var c counts
	if err := tx.QueryRow(ctx, `SELECT per_minute, per_day FROM mail_server`).Scan(&c.perMinute, &c.perDay); err != nil {
		return c, err
	}
	err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '1 minute'),
			count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '24 hours'),
			coalesce(extract(epoch FROM min(sent_at) FILTER (WHERE sent_at > clock_timestamp() - interval '1 minute')
				+ interval '1 minute' - clock_timestamp()), 0)::float8,
			count(*) FILTER (WHERE kind = 'admin' AND sent_by IS NOT DISTINCT FROM $1 AND sent_at > clock_timestamp() - interval '1 hour'),
			coalesce(extract(epoch FROM min(sent_at) FILTER (WHERE kind = 'admin' AND sent_by IS NOT DISTINCT FROM $1
				AND sent_at > clock_timestamp() - interval '1 hour') + interval '1 hour' - clock_timestamp()), 0)::float8,
			count(*) FILTER (WHERE kind = 'admin' AND organization_id = $2 AND sent_at > clock_timestamp() - interval '24 hours'),
			coalesce(extract(epoch FROM min(sent_at) FILTER (WHERE kind = 'admin' AND organization_id = $2
				AND sent_at > clock_timestamp() - interval '24 hours') + interval '24 hours' - clock_timestamp()), 0)::float8,
			EXISTS (SELECT 1 FROM mail_waits WHERE until > clock_timestamp())
		FROM mail_sends`, ch.admin, ch.organization).Scan(&c.minute, &c.day, &c.minuteWait, &c.admin, &c.adminWait, &c.organization,
		&c.organizationWait, &c.waiting)
	return c, err
}

// refusal says which limit stops a message, nil when none does.
func (c counts) refusal(ch charge) *LimitError {
	le := &LimitError{Kind: string(ch.kind), PerMinute: c.perMinute, PerDay: c.perDay}
	admin := ch.kind == kindAdmin
	switch {
	case admin && c.admin >= AdminPerHour:
		le.Admin, le.RetryAfter = true, secondsDuration(c.adminWait)
	case admin && ch.organization != nil && c.organization >= OrganizationPerDay:
		le.Organization, le.RetryAfter = true, secondsDuration(c.organizationWait)
	case c.day >= ch.kind.dayLimit(c.perDay):
		le.Day = true
	case c.minute >= c.perMinute:
		le.RetryAfter = secondsDuration(c.minuteWait)
	case ch.kind == kindOther && c.waiting:
		le.AccountWaiting = true
	default:
		return nil
	}
	return le
}

// tryTake counts one message if the limits have room, and otherwise says
// which limit is reached.
func (s *Service) tryTake(ctx context.Context, ch charge) (int64, *LimitError, error) {
	var id int64
	var refused *LimitError
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockMail)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mail_sends WHERE sent_at <= clock_timestamp() - interval '24 hours'`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mail_waits WHERE until <= clock_timestamp()`); err != nil {
			return err
		}
		c, err := readCounts(ctx, tx, ch)
		if err != nil {
			return err
		}
		// A refusal is an answer, not a failure: the transaction commits
		// the clean-up above, and nothing is counted.
		if refused = c.refusal(ch); refused == nil {
			return tx.QueryRow(ctx, `INSERT INTO mail_sends (kind, sent_by, organization_id) VALUES ($1, $2, $3) RETURNING id`,
				string(ch.kind), ch.admin, ch.organization).Scan(&id)
		}
		return nil
	})
	return id, refused, err
}

// AdminRoom says whether an administrator may email the account by names
// an invitation or a password link now, under the limits on one
// administrator and one organization: nil, or a 429 error that says when
// to try again. It is asked before the link is made, so that nothing is
// made that cannot be sent; the limits are taken again, under the lock,
// as the message goes.
func (s *Service) AdminRoom(ctx context.Context, by mailer.AccountMail) error {
	ch := accountCharge(by)
	if ch.kind != kindAdmin {
		return nil
	}
	var refused *LimitError
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		c, err := readCounts(ctx, tx, ch)
		refused = c.refusal(ch)
		return err
	})
	switch {
	case err != nil:
		return err
	case refused != nil && refused.Admin:
		return apperr.TooMany("admin_mail_limited", refused.Error())
	case refused != nil && refused.Organization:
		return apperr.TooMany("organization_mail_limited", refused.Error())
	}
	return nil
}

// wait records account mail waiting for room for up to d, so that other
// mail stands back on every server; unwait removes it.
func (s *Service) wait(ctx context.Context, d time.Duration) (int64, error) {
	var id int64
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `INSERT INTO mail_waits (until) VALUES (clock_timestamp() + make_interval(secs => $1)) RETURNING id`,
			d.Seconds()).Scan(&id)
	})
	return id, err
}

func (s *Service) unwait(id int64) {
	s.forget(`DELETE FROM mail_waits WHERE id = $1`, id, "mail server: ending a wait for room under the limits")
}

// untake stops counting a message the mail server did not take.
func (s *Service) untake(id int64) {
	s.forget(`DELETE FROM mail_sends WHERE id = $1`, id, "mail server: uncounting a message that was not sent")
}

// forget deletes a row of the limits' own, even when the request that took
// it has ended.
func (s *Service) forget(q string, id int64, what string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, q, id)
		return err
	}); err != nil {
		s.log.Error(what, "error", err)
	}
}

// usage counts the messages of the last minute and day.
func usage(ctx context.Context, tx pgx.Tx, perDay int) (Usage, error) {
	u := Usage{OtherDayLimit: kindOther.dayLimit(perDay), AdminDayLimit: kindAdmin.dayLimit(perDay)}
	err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '1 minute'),
		count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '24 hours'),
		count(*) FILTER (WHERE kind <> 'other' AND sent_at > clock_timestamp() - interval '24 hours')
		FROM mail_sends`).Scan(&u.LastMinute, &u.LastDay, &u.AccountLastDay)
	return u, err
}

// SendAccountMail sends msg to one person's own account (an invitation, a
// password reset) through the mail server in force, ahead of every other
// mail, counted against by: it waits for room under the minute's limit,
// and may use more of the day's than other mail (see kind).
func (s *Service) SendAccountMail(ctx context.Context, to string, msg mailer.Message, by mailer.AccountMail) error {
	cfg, err := s.InForce(ctx)
	if err != nil {
		return err
	}
	if cfg == nil {
		return ErrNoMailServer
	}
	m, err := mailer.New(*cfg)
	if err != nil {
		return err
	}
	return mailer.FirstError(m.Send(ctx, msg, []string{to}, s.gate(accountCharge(by))))
}

// TestInput is a test message to send.
type TestInput struct {
	// To is the address to send it to.
	To string `json:"to"`
	// Server is the console's form, saved or not, so that a mail server can
	// be tried before it is saved; nil tests the mail server in force. It
	// must be nil while .env's mail server is in force.
	Server *Input `json:"server,omitempty"`
}

// TestResult is how the test went: the mail server's answer, or why
// nothing was sent.
type TestResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// testLetter is the test message: EasyRMM's own words only, so that the
// test cannot carry anyone's text.
var testLetter = mailer.Letter{
	Subject: "EasyRMM test message",
	Before: []string{
		"This is a test message from EasyRMM.",
		"It came through the mail server EasyRMM sends invitations, password resets and notifications with. If you are reading it, mail from EasyRMM reaches this address.",
	},
	After: []string{"You do not need to do anything."},
}

// Test sends the test message, at most one every TestInterval, and records
// it in the audit log.
func (s *Service) Test(ctx context.Context, actor audit.Actor, in TestInput) (TestResult, error) {
	in.To = strings.TrimSpace(in.To)
	if !mailer.BareAddress(in.To) {
		return TestResult{}, apperr.Invalid("to", "Enter one email address to send the test message to.")
	}
	source := FromConsole
	var cfg *mailer.Config
	switch {
	case s.env != nil:
		if in.Server != nil {
			return TestResult{}, ErrFromEnv
		}
		source, cfg = FromEnv, s.env
	case in.Server != nil:
		var stored *row
		if err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			var err error
			stored, err = loadRow(ctx, tx, false)
			return err
		}); err != nil {
			return TestResult{}, err
		}
		c, err := s.check(in.Server, stored)
		if err != nil {
			return TestResult{}, err
		}
		cfg = &c
	default:
		var err error
		if cfg, err = s.InForce(ctx); err != nil {
			return TestResult{}, err
		}
		if cfg == nil {
			return TestResult{}, ErrNoMailServer
		}
	}
	if err := s.testSlot(ctx); err != nil {
		return TestResult{}, err
	}
	msg, err := testLetter.Message()
	if err != nil {
		return TestResult{}, err
	}
	m, err := mailer.New(*cfg)
	if err != nil {
		return TestResult{}, err
	}
	out := m.Send(ctx, msg, []string{in.To}, s.gate(charge{kind: kindOther}))[0]
	res := TestResult{OK: out.Err == nil}
	// The sender as it went, never the password.
	signIn := SignInNone
	if cfg.Username != "" {
		signIn = SignInPassword
	}
	details := map[string]any{"to": in.To, "source": source, "host": cfg.Host, "port": cfg.Port, "security": cfg.Security,
		"signIn": signIn, "username": cfg.Username, "fromAddress": cfg.FromAddress, "fromName": cfg.FromName}
	outcome := audit.Success
	if res.OK {
		res.Message = fmt.Sprintf("Sent. %s took the message for %s and answered: %s", m.Address(), in.To, out.Reply)
	} else {
		res.Message = strings.TrimPrefix(out.Err.Error(), "mailer: ")
		outcome, details["error"] = audit.Failure, res.Message
	}
	err = s.audit.Record(ctx, audit.Event{Actor: actor, Action: "mail_server.test", Outcome: outcome, TargetType: "mail_server",
		TargetID: net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port)), Details: details})
	return res, err
}

// testSlot takes the one test message allowed every TestInterval, across
// servers.
func (s *Service) testSlot(ctx context.Context) error {
	return s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		var wait float64
		err := tx.QueryRow(ctx, `UPDATE mail_server SET last_test_at = clock_timestamp()
			WHERE last_test_at IS NULL OR last_test_at <= clock_timestamp() - make_interval(secs => $1)
			RETURNING 0::float8`, TestInterval.Seconds()).Scan(&wait)
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT extract(epoch FROM last_test_at + make_interval(secs => $1) - clock_timestamp())::float8
			FROM mail_server`, TestInterval.Seconds()).Scan(&wait); err != nil {
			return err
		}
		return &TooSoonError{RetryAfter: time.Duration(wait * float64(time.Second))}
	})
}

// secondsDuration is n seconds, from the database.
func secondsDuration(n float64) time.Duration { return time.Duration(n * float64(time.Second)) }

// waitWords says d in words for a message, rounded up: "40 seconds", "12
// minutes", "3 hours".
func waitWords(d time.Duration) string {
	switch {
	case d <= time.Minute:
		return plural(seconds(d), "second")
	case d <= time.Hour:
		return plural(int((d+time.Minute-1)/time.Minute), "minute")
	default:
		return plural(int((d+time.Hour-1)/time.Hour), "hour")
	}
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// thousands writes n with commas between thousands.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
