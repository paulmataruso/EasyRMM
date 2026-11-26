package app

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/paulmataruso/easyrmm/server/internal/database"
	"github.com/paulmataruso/easyrmm/server/internal/mailer"
	"github.com/paulmataruso/easyrmm/server/internal/mailserver"
)

// quickAssistFlood mails an organization's administrators that a permanent
// Quick Assist link is being used faster than its limit (ADR-0080), through
// the mail server in force. Without one, nothing is sent; the audit row
// still says so.
func quickAssistFlood(db *database.DB, mail *mailserver.Service, log *slog.Logger) func(context.Context, uuid.UUID, string) {
	return func(ctx context.Context, org uuid.UUID, link string) {
		type to struct {
			id    uuid.UUID
			email string
		}
		var admins []to
		err := db.ReadTx(ctx, database.System, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT DISTINCT u.id, u.email FROM users u JOIN role_assignments a ON a.user_id = u.id
				WHERE u.status = 'active' AND a.role = 'org_admin' AND a.organization_id = $1`, org)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var t to
				if err := rows.Scan(&t.id, &t.email); err != nil {
					return err
				}
				admins = append(admins, t)
			}
			return rows.Err()
		})
		if err != nil {
			log.Warn("quick assist: reading administrators for the flood mail failed", "error", err)
			return
		}
		msg := mailer.Message{
			Subject: "Quick Assist link is being used too fast",
			Text: "The Quick Assist link \"" + link + "\" went over its limit: requests are being turned away. " +
				"If you do not expect this, pause or revoke the link under Quick Assist, Links. You get this mail once a day per link.",
		}
		for _, a := range admins {
			if err := mail.SendAccountMail(ctx, a.email, msg, mailer.AccountMail{Account: a.id, Organization: org}); err != nil {
				log.Info("quick assist: the flood mail was not sent", "error", err)
			}
		}
	}
}
