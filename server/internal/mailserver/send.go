package mailserver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/apperr"
	"github.com/paulmataruso/easyrmm/server/internal/audit"
	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/m365"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
)

// lockMail serializes taking room under the limits, across servers.
const lockMail = 4471209853361

// accountWait is the longest account mail waits for room under the
// minute's limit.
const accountWait = 65 * time.Second

// AccountLimits are the limits on account mail, decided in review of #82
// (ADR-0053), so that no administrator, organization or account, and no one
// who knows people's addresses, can use up the platform's mail. Each but an
// account's is the smaller of a number and a share of the day's limit, so
// that a low day's limit keeps them small too, and at least one. mail.md
// says why each is what it is.
type AccountLimits struct {
	// AdminPerHour: invitations and password links one administrator
	// emails in an hour. The smaller of 60 and a 150th of the day: one at
	// it all day uses at most 16% of the day.
	AdminPerHour int `json:"adminPerHour"`
	// OrganizationPerDay: invitations and password links administrators,
	// other than super administrators, email to one organization's accounts
	// in 24 hours. The smaller of 500 and an 18th (5.6%) of the day.
	OrganizationPerDay int `json:"organizationPerDay"`
	// AccountBurst and AccountEveryMinutes: password emails to one
	// account, resets people ask for and administrators' links together:
	// AccountBurst at once, then one every AccountEveryMinutes.
	AccountBurst        int `json:"accountBurst"`
	AccountEveryMinutes int `json:"accountEveryMinutes"`
	// ResetsPerHour: password resets people ask for, on the whole platform,
	// in an hour. The smaller of 60 and a 300th of the day: kept up all day,
	// 8% of it, less than the 10% kept for them.
	ResetsPerHour int `json:"resetsPerHour"`
	// OrganizationResetsPerHour: password resets people ask for, to one
	// organization's accounts (accounts in no one organization counting
	// together as one), in an hour: a third of the platform's hour, so that
	// the rest is there for the others. No limit a day holds resets, so
	// that no one can keep them refused longer than an hour after they
	// stop asking.
	OrganizationResetsPerHour int `json:"organizationResetsPerHour"`
}

// accountLimits are the limits on account mail at a day's limit of perDay.
func accountLimits(perDay int) AccountLimits {
	share := func(most, part int) int { return max(1, min(most, perDay/part)) }
	resets := share(60, 300)
	return AccountLimits{
		AdminPerHour:              share(60, 150),
		OrganizationPerDay:        share(500, 18),
		AccountBurst:              3,
		AccountEveryMinutes:       20,
		ResetsPerHour:             resets,
		OrganizationResetsPerHour: max(1, resets/3),
	}
}

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
	// admin, for kindAdmin; account and organization, for account mail:
	// nil for none.
	admin, account, organization *uuid.UUID
}

func accountCharge(by mailer.AccountMail) charge {
	ch := charge{kind: kindAdmin}
	if by.Self {
		ch.kind = kindReset
	} else if by.Admin != uuid.Nil {
		ch.admin = &by.Admin
	}
	if by.Account != uuid.Nil {
		ch.account = &by.Account
	}
	if by.Organization != uuid.Nil {
		ch.organization = &by.Organization
	}
	return ch
}

// LimitError is a message the limits did not let go. It is a
// mailer.Limited.
type LimitError struct {
	// Code is the limit reached, a mailer.Limit code.
	Code string
	// Kind is reset, admin or other (see kind).
	Kind       string
	PerMinute  int
	PerDay     int
	Limits     AccountLimits
	RetryAfter time.Duration
}

// LimitCode names the limit reached.
func (e *LimitError) LimitCode() string { return e.Code }

// RetryIn is how long until there is room, 0 when unknown.
func (e *LimitError) RetryIn() time.Duration { return e.RetryAfter }

func (e *LimitError) Error() string {
	switch e.Code {
	case mailer.LimitAdmin:
		return fmt.Sprintf("You have emailed %s invitations and password links in the last hour, the most one administrator may. Try again in %s.",
			thousands(e.Limits.AdminPerHour), waitWords(e.RetryAfter))
	case mailer.LimitOrganization:
		return fmt.Sprintf("This organization's accounts have been emailed %s invitations and password links in the last 24 hours, the most one organization may; more can be emailed in %s.",
			thousands(e.Limits.OrganizationPerDay), waitWords(e.RetryAfter))
	case mailer.LimitAccount:
		return fmt.Sprintf("This account has been emailed as many password emails as one account may: %d at once, then one every %d minutes. Another can be emailed in %s.",
			e.Limits.AccountBurst, e.Limits.AccountEveryMinutes, waitWords(e.RetryAfter))
	case mailer.LimitOrganizationResets:
		return fmt.Sprintf("Password resets to this organization's accounts reach their limit of %d an hour; more can be sent in %s.",
			e.Limits.OrganizationResetsPerHour, waitWords(e.RetryAfter))
	case mailer.LimitResets:
		return fmt.Sprintf("Password resets reach the limit of %d an hour; more can be sent in %s.", e.Limits.ResetsPerHour, waitWords(e.RetryAfter))
	case mailer.LimitDay:
		switch e.Kind {
		case string(kindReset):
			return fmt.Sprintf("Not sent: the limit of %s messages a day is reached. Raise it under Settings → Notifications → Mail server, or wait until the oldest of them is 24 hours old.",
				thousands(e.PerDay))
		case string(kindAdmin):
			return fmt.Sprintf("Not sent: messages in the last 24 hours reach %s, 90%% of the limit of %s a day; the rest is kept for password resets people ask for.",
				thousands(kindAdmin.dayLimit(e.PerDay)), thousands(e.PerDay))
		}
		return fmt.Sprintf("Not sent: messages in the last 24 hours reach %s, 80%% of the limit of %s a day; the rest is kept for invitations and password resets.",
			thousands(kindOther.dayLimit(e.PerDay)), thousands(e.PerDay))
	case mailer.LimitAccountWaiting:
		return fmt.Sprintf("Not sent: invitations or password resets are waiting for room under the limit of %s messages a minute, and go first. Try again in a minute.",
			thousands(e.PerMinute))
	}
	return fmt.Sprintf("Not sent: the limit of %s messages a minute is reached. Try again in %d seconds.", thousands(e.PerMinute), seconds(e.RetryAfter))
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
// wait, and no mail waits for any other limit.
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
		case refused.Code != mailer.LimitMinute || ch.kind == kindOther || time.Now().Add(refused.RetryAfter).After(until):
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

// counts is what the limits count for one message. Each wait is how long
// until that count has room, in seconds.
type counts struct {
	perMinute, perDay int
	minute, day       int
	minuteWait        float64
	// admin: the administrator's mail in the last hour; organization: the
	// organization's administrators' mail in the last 24 hours.
	admin, organization         int
	adminWait, organizationWait float64
	// accountFull: when the account's bucket, from the password emails
	// that left mail_sends, is full again, in seconds from now; -Inf
	// without one. accountAges: the ages, in seconds, of the password
	// emails to the account still in mail_sends, oldest first.
	accountFull float64
	accountAges []float64
	// resetsHour: resets people asked for in the last hour, everywhere;
	// orgResetsHour, to the organization's accounts.
	resetsHour, orgResetsHour         int
	resetsHourWait, orgResetsHourWait float64
	// waiting: account mail is waiting for room, on some server.
	waiting bool
}

func readCounts(ctx context.Context, tx pgx.Tx, ch charge) (counts, error) {
	var c counts
	if err := tx.QueryRow(ctx, `SELECT per_minute, per_day FROM mail_server`).Scan(&c.perMinute, &c.perDay); err != nil {
		return c, err
	}
	// n counts the rows where cond holds within the window, and wait is
	// how long until the oldest of them leaves it.
	n := func(cond, window string) string {
		return `count(*) FILTER (WHERE ` + cond + ` AND sent_at > clock_timestamp() - interval '` + window + `'),
			coalesce(extract(epoch FROM min(sent_at) FILTER (WHERE ` + cond + ` AND sent_at > clock_timestamp() - interval '` + window + `')
				+ interval '` + window + `' - clock_timestamp()), 0)::float8`
	}
	// $1 the administrator, $2 the organization, $3 the account; reset
	// rows in no one organization count together.
	err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE sent_at > clock_timestamp() - interval '24 hours'),
			`+n(`true`, `1 minute`)+`,
			`+n(`kind = 'admin' AND sent_by IS NOT DISTINCT FROM $1`, `1 hour`)+`,
			`+n(`kind = 'admin' AND organization_id = $2`, `24 hours`)+`,
			`+n(`kind = 'reset'`, `1 hour`)+`,
			`+n(`kind = 'reset' AND organization_id IS NOT DISTINCT FROM $2`, `1 hour`)+`,
			EXISTS (SELECT 1 FROM mail_waits WHERE until > clock_timestamp())
		FROM mail_sends`, ch.admin, ch.organization).Scan(&c.day, &c.minute, &c.minuteWait, &c.admin, &c.adminWait,
		&c.organization, &c.organizationWait, &c.resetsHour, &c.resetsHourWait, &c.orgResetsHour, &c.orgResetsHourWait, &c.waiting)
	if err != nil || ch.account == nil {
		return c, err
	}
	// The bucket carried from the emails folded out of mail_sends, then
	// every email still in it, of any age: an email leaves mail_sends only
	// as it is folded into the bucket (foldAccounts), so the two together
	// are every email the account was sent.
	c.accountFull = math.Inf(-1)
	err = tx.QueryRow(ctx, `SELECT extract(epoch FROM full_at - clock_timestamp())::float8 FROM mail_account_buckets WHERE account_id = $1`,
		ch.account).Scan(&c.accountFull)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return c, err
	}
	rows, err := tx.Query(ctx, `SELECT extract(epoch FROM clock_timestamp() - sent_at)::float8 FROM mail_sends
		WHERE account_id = $1 ORDER BY sent_at`, ch.account)
	if err != nil {
		return c, err
	}
	c.accountAges, err = pgx.CollectRows(rows, pgx.RowTo[float64])
	return c, err
}

// accountRoomIn is how long, in seconds, until an account may be sent
// another password email, at burst at once and then one every every
// seconds; 0 when it may now. full is when its bucket, from the emails no
// longer in mail_sends, is full again, in seconds from now (-Inf for
// none); ages are the ages of the others, oldest first. It is a token
// bucket, worked out from the emails themselves (the generic cell rate
// algorithm): each email moves the time the bucket is full again on by
// every, from then or from when it was sent, whichever is later.
func accountRoomIn(full float64, ages []float64, burst int, every float64) float64 {
	for _, a := range ages {
		full = max(full, -a) + every
	}
	return max(0, full-float64(burst-1)*every)
}

// foldAccounts folds the password emails leaving mail_sends, oldest first,
// into their accounts' buckets, exactly as accountRoomIn counts them, so
// that the limit per account holds past the 24 hours mail_sends keeps; and
// drops buckets that no longer change anything: full more than 24 hours
// ago, before any email still in mail_sends was sent. Call it under
// lockMail, as it deletes the rows it folds.
func foldAccounts(ctx context.Context, tx pgx.Tx, every time.Duration) error {
	rows, err := tx.Query(ctx, `WITH aged AS (
			DELETE FROM mail_sends WHERE sent_at <= clock_timestamp() - interval '24 hours' RETURNING account_id, sent_at)
		SELECT account_id, sent_at FROM aged WHERE account_id IS NOT NULL ORDER BY account_id, sent_at`)
	if err != nil {
		return err
	}
	type sent struct {
		account uuid.UUID
		at      time.Time
	}
	aged, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (sent, error) {
		var s sent
		return s, r.Scan(&s.account, &s.at)
	})
	if err != nil {
		return err
	}
	for i := 0; i < len(aged); {
		account := aged[i].account
		var full time.Time
		err := tx.QueryRow(ctx, `SELECT full_at FROM mail_account_buckets WHERE account_id = $1`, account).Scan(&full)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		for ; i < len(aged) && aged[i].account == account; i++ {
			if aged[i].at.After(full) {
				full = aged[i].at
			}
			full = full.Add(every)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mail_account_buckets (account_id, full_at) VALUES ($1, $2)
			ON CONFLICT (account_id) DO UPDATE SET full_at = excluded.full_at`, account, full); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `DELETE FROM mail_account_buckets WHERE full_at <= clock_timestamp() - interval '24 hours'`)
	return err
}

// refusal says which limit stops a message, nil when none does.
func (c counts) refusal(ch charge) *LimitError {
	l := accountLimits(c.perDay)
	le := &LimitError{Kind: string(ch.kind), PerMinute: c.perMinute, PerDay: c.perDay, Limits: l}
	refuse := func(code string, wait float64) *LimitError {
		le.Code, le.RetryAfter = code, secondsDuration(wait)
		return le
	}
	admin, reset := ch.kind == kindAdmin, ch.kind == kindReset
	accountIn := accountRoomIn(c.accountFull, c.accountAges, l.AccountBurst, float64(l.AccountEveryMinutes*60))
	switch {
	case admin && c.admin >= l.AdminPerHour:
		return refuse(mailer.LimitAdmin, c.adminWait)
	case ch.account != nil && accountIn > 0:
		return refuse(mailer.LimitAccount, accountIn)
	case admin && ch.organization != nil && c.organization >= l.OrganizationPerDay:
		return refuse(mailer.LimitOrganization, c.organizationWait)
	case reset && c.orgResetsHour >= l.OrganizationResetsPerHour:
		return refuse(mailer.LimitOrganizationResets, c.orgResetsHourWait)
	case reset && c.resetsHour >= l.ResetsPerHour:
		return refuse(mailer.LimitResets, c.resetsHourWait)
	case c.day >= ch.kind.dayLimit(c.perDay):
		return refuse(mailer.LimitDay, 0)
	case c.minute >= c.perMinute:
		return refuse(mailer.LimitMinute, c.minuteWait)
	case ch.kind == kindOther && c.waiting:
		return refuse(mailer.LimitAccountWaiting, 0)
	}
	return nil
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
		// Emails a day old leave mail_sends, into their accounts' buckets.
		// The per-account rate is the same at every day's limit.
		if err := foldAccounts(ctx, tx, time.Duration(accountLimits(0).AccountEveryMinutes)*time.Minute); err != nil {
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
			return tx.QueryRow(ctx, `INSERT INTO mail_sends (kind, sent_by, organization_id, account_id) VALUES ($1, $2, $3, $4) RETURNING id`,
				string(ch.kind), ch.admin, ch.organization, ch.account).Scan(&id)
		}
		return nil
	})
	return id, refused, err
}

// Room says whether account mail counted against by has room under the
// limits now, as far as a read can tell: nil, or the *LimitError of the
// limit reached. It is asked before a link is made, so that a reset is not
// made that cannot be sent, and an administrator past their own limit is
// told so; the limits are taken again, under the lock, as the message
// goes.
func (s *Service) Room(ctx context.Context, by mailer.AccountMail) error {
	ch := accountCharge(by)
	var refused *LimitError
	err := s.db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
		c, err := readCounts(ctx, tx, ch)
		if err == nil {
			refused = c.refusal(ch)
		}
		return err
	})
	if err != nil {
		return err
	}
	if refused != nil {
		return refused
	}
	return nil
}

// Reserve takes room under the limits for one message of account mail
// counted against by, as SendAccountMail would, before the message is
// made: a password reset's link is made only when it can be sent, since
// each new one ends the last. A limit that stops it is a *LimitError. The
// reservation is sent, or released, once. Its message, sent after the
// request for it has been answered, is tried once more a minute later
// when the mail server refuses it for its rate.
func (s *Service) Reserve(ctx context.Context, by mailer.AccountMail) (mailer.Reservation, error) {
	id, err := s.take(ctx, accountCharge(by))
	if err != nil {
		return nil, err
	}
	return &reservation{s: s, id: id}, nil
}

// reservation is room under the limits taken for one message.
type reservation struct {
	s    *Service
	id   int64
	mu   sync.Mutex
	used bool
}

// claim uses the reservation, once.
func (r *reservation) claim() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	used := r.used
	r.used = true
	return !used
}

// Send sends msg to one person through the mail server in force, in the
// room reserved; the room is given back when the mail server does not
// take it.
func (r *reservation) Send(ctx context.Context, to string, msg mailer.Message) error {
	if !r.claim() {
		return errors.New("mailserver: the room reserved for this message was used")
	}
	gave := false
	defer func() {
		if !gave {
			r.s.untake(r.id)
		}
	}()
	cfg, err := r.s.InForce(ctx)
	if err != nil {
		return err
	}
	if cfg == nil {
		return ErrNoMailServer
	}
	cfg.RateRetry = r.s.rateRetry
	m, err := mailer.New(*cfg)
	if err != nil {
		return err
	}
	return mailer.FirstError(m.Send(ctx, msg, []string{to}, func(context.Context) (func(), error) {
		gave = true
		return func() { r.s.untake(r.id) }, nil
	}))
}

// Release gives the room back, unless the message was sent.
func (r *reservation) Release() {
	if r.claim() {
		r.s.untake(r.id)
	}
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
	// Not tried again for the mail server's rate: an administrator's
	// request waits for this, and the link comes back to them with the
	// reason at once (decided in review).
	m, err := mailer.New(*cfg)
	if err != nil {
		return err
	}
	return mailer.FirstError(m.Send(ctx, msg, []string{to}, s.gate(accountCharge(by))))
}

// SendNotification sends one notification message to each recipient through
// the mail server in force, counted against the limits as other mail: it
// stops at 80% of the day's, so that account mail always has room, and is
// never waited for. A message the limits did not let go is a LimitError, one
// the mail server refused a mailer.ReplyError, per recipient (ADR-0053).
func (s *Service) SendNotification(ctx context.Context, to []string, msg mailer.Message) ([]mailer.Outcome, error) {
	cfg, err := s.InForce(ctx)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, ErrNoMailServer
	}
	m, err := mailer.New(*cfg)
	if err != nil {
		return nil, err
	}
	return m.Send(ctx, msg, to, s.gate(charge{kind: kindOther})), nil
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
	var app *m365.Credentials
	switch {
	case s.env != nil:
		if in.Server != nil {
			return TestResult{}, ErrFromEnv
		}
		source, cfg, app = FromEnv, s.env, s.envApp
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
		cfg, app = &c.cfg, c.app
	default:
		var err error
		if cfg, app, err = s.inForce(ctx); err != nil {
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
	// The sender as it went, never the password, the secret or the key.
	signIn := SignInNone
	if cfg.Username != "" {
		signIn = SignInPassword
	}
	details := map[string]any{"to": in.To, "source": source, "host": cfg.Host, "port": cfg.Port, "security": cfg.Security,
		"signIn": signIn, "username": cfg.Username, "fromAddress": cfg.FromAddress, "fromName": cfg.FromName}
	if app != nil {
		details["signIn"], details["username"] = SignInMicrosoft365, ""
		details["tenantId"], details["clientId"], details["credential"] = app.TenantID, app.ClientID, app.Kind()
	}
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
