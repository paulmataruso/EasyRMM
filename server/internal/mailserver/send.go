package mailserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

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

// LimitError is a message the limits did not let go.
type LimitError struct {
	// Day is the day's limit reached; otherwise the minute's.
	Day bool
	// Account is account mail refused; otherwise other mail, which stops at
	// 90% of the day's limit and stands back while account mail waits.
	Account bool
	// AccountWaiting is other mail standing back for account mail.
	AccountWaiting bool
	PerMinute      int
	PerDay         int
	RetryAfter     time.Duration
}

func (e *LimitError) Error() string {
	switch {
	case e.Day && e.Account:
		return fmt.Sprintf("Not sent: the limit of %s messages a day is reached. Raise it under Settings → Notifications → Mail server, or wait until the oldest of them is 24 hours old.",
			thousands(e.PerDay))
	case e.Day:
		return fmt.Sprintf("Not sent: messages in the last 24 hours reach %s, 90%% of the limit of %s a day; the rest is kept for invitations and password resets.",
			thousands(e.PerDay*9/10), thousands(e.PerDay))
	case e.AccountWaiting:
		return fmt.Sprintf("Not sent: invitations or password resets are waiting for room under the limit of %s messages a minute, and go first. Try again in a minute.",
			thousands(e.PerMinute))
	default:
		return fmt.Sprintf("Not sent: the limit of %s messages a minute is reached. Try again in %d seconds.", thousands(e.PerMinute), seconds(e.RetryAfter))
	}
}

// gate counts each message against the limits.
func (s *Service) gate(account bool) mailer.Gate {
	return func(ctx context.Context) (func(), error) {
		id, err := s.take(ctx, account)
		if err != nil {
			return nil, err
		}
		return func() { s.untake(id) }, nil
	}
}

// take makes room for one message under the limits and counts it. Account
// mail waits up to accountWait for room under the minute's limit; other
// mail does not wait, and stands back while account mail waits.
func (s *Service) take(ctx context.Context, account bool) (int64, error) {
	until := time.Now().Add(accountWait)
	if account {
		s.accountWaiting.Add(1)
		defer s.accountWaiting.Add(-1)
	}
	for {
		id, refused, err := s.tryTake(ctx, account)
		switch {
		case err != nil:
			return 0, err
		case refused == nil:
			return id, nil
		case refused.Day || !account || time.Now().Add(refused.RetryAfter).After(until):
			return 0, refused
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

// tryTake counts one message if the limits have room, and otherwise says
// which limit is reached.
func (s *Service) tryTake(ctx context.Context, account bool) (int64, *LimitError, error) {
	var id int64
	var refused *LimitError
	err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(lockMail)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM mail_sends WHERE sent_at <= clock_timestamp() - interval '24 hours'`); err != nil {
			return err
		}
		var perMinute, perDay, minute, day int
		var wait float64
		if err := tx.QueryRow(ctx, `SELECT per_minute, per_day FROM mail_server`).Scan(&perMinute, &perDay); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '1 minute'), count(*),
			coalesce(extract(epoch FROM min(sent_at) FILTER (WHERE sent_at > clock_timestamp() - interval '1 minute')
				+ interval '1 minute' - clock_timestamp()), 0)::float8
			FROM mail_sends`).Scan(&minute, &day, &wait); err != nil {
			return err
		}
		le := &LimitError{Account: account, PerMinute: perMinute, PerDay: perDay, RetryAfter: time.Duration(wait * float64(time.Second))}
		dayLimit := perDay
		if !account {
			dayLimit = perDay * 9 / 10
		}
		switch {
		case day >= dayLimit:
			le.Day = true
			refused = le
			return nil
		case minute >= perMinute:
			refused = le
			return nil
		case !account && s.accountWaiting.Load() > 0:
			le.AccountWaiting = true
			refused = le
			return nil
		}
		return tx.QueryRow(ctx, `INSERT INTO mail_sends (account) VALUES ($1) RETURNING id`, account).Scan(&id)
	})
	return id, refused, err
}

// untake stops counting a message the mail server did not take.
func (s *Service) untake(id int64) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.db.InTx(ctx, database.System, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM mail_sends WHERE id = $1`, id)
		return err
	}); err != nil {
		s.log.Error("mail server: uncounting a message that was not sent", "error", err)
	}
}

// usage counts the messages of the last minute and day.
func usage(ctx context.Context, tx pgx.Tx, perDay int) (Usage, error) {
	u := Usage{OtherDayLimit: perDay * 9 / 10}
	err := tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '1 minute'),
		count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '24 hours'),
		count(*) FILTER (WHERE account AND sent_at > clock_timestamp() - interval '24 hours')
		FROM mail_sends`).Scan(&u.LastMinute, &u.LastDay, &u.AccountLastDay)
	return u, err
}

// SendAccountMail sends msg to one person's own account (an invitation, a
// password reset) through the mail server in force, ahead of every other
// mail: it counts against the limits, may use the whole day's, and waits
// for room under the minute's.
func (s *Service) SendAccountMail(ctx context.Context, to string, msg mailer.Message) error {
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
	return mailer.FirstError(m.Send(ctx, msg, []string{to}, s.gate(true)))
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
	out := m.Send(ctx, msg, []string{in.To}, s.gate(false))[0]
	res := TestResult{OK: out.Err == nil}
	details := map[string]any{"to": in.To, "source": source, "host": cfg.Host, "port": cfg.Port, "security": cfg.Security}
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

// thousands writes n with commas between thousands.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
