package mailer

import (
	"strings"
)

// Exchange Online's replies, explained (ADR-0053, slice 2): what a refusal
// means and the setting that changes it. The texts are those Microsoft's
// documentation and forums give; a reply not recognized is shown as given.

// hint says what the mail server's reply means and what to change, "" when
// it is not one EasyRMM knows. xoauth says the sign-in was AUTH XOAUTH2,
// with a Microsoft 365 application's token.
func hint(step string, code int, text string, xoauth bool) string {
	t := strings.ToLower(text)
	has := func(s string) bool { return strings.Contains(t, strings.ToLower(s)) }
	switch {
	case has("SmtpClientAuthentication is disabled for the Tenant"):
		return "SMTP AUTH is turned off for the whole organization in Exchange Online. An Exchange administrator turns it on for the sending mailbox alone with " +
			"Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false (the mailbox's setting wins over the organization's), " +
			"or for the organization with Set-TransportConfig -SmtpClientAuthenticationDisabled $false. With Entra's security defaults on, SMTP AUTH stays off whatever these say."
	case has("SmtpClientAuthentication is disabled for the Mailbox"):
		return "SMTP AUTH is turned off for the sending mailbox. An Exchange administrator turns it on with " +
			"Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false."
	case has("SmtpClientAuthentication is disabled"):
		return "SMTP AUTH is turned off for the sending mailbox or for the organization in Exchange Online: " +
			"Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false turns it on for the mailbox, which wins over the organization's setting."
	case has("security defaults"):
		return "The tenant has Entra's security defaults on, which turn SMTP AUTH off, OAuth included. Turn them off (and protect sign-in otherwise, " +
			"such as with Conditional Access), or send through a relay."
	case has("basic authentication is disabled"):
		return "Exchange Online no longer takes a password over SMTP in this tenant. Sign in with a Microsoft 365 application instead, or send through a relay."
	case step == "sign-in" && code == 535 && xoauth && has("5.7.3"):
		return "Exchange Online did not take the application's token for this mailbox. Check that the application has the SMTP.SendAsApp application permission " +
			"(Office 365 Exchange Online) with an administrator's consent, that its service principal is registered in Exchange with New-ServicePrincipal " +
			"(with the Enterprise application's Object ID, not the App registration's), that it was given the mailbox with Add-MailboxPermission, " +
			"and that SMTP AUTH is on for the mailbox."
	case has("SendAsDenied") || has("5.7.60") || has("not have permissions to send as"):
		if xoauth {
			return "Exchange Online does not let the application send as this address. Give its service principal the mailbox with " +
				"Add-MailboxPermission -AccessRights FullAccess, or, for an address other than the mailbox's own, Add-RecipientPermission -AccessRights SendAs."
		}
		return "The account signed in to may not send as the sender's address: send as the account's own address, or give it the right to send as this one."
	case has("Sender throttled due to continuous"):
		return "Exchange Online throttles this mailbox after repeated errors of one kind. Correct their cause; the mailbox sends again once Microsoft's throttling period ends."
	case has("SubmissionQuotaExceeded"):
		return "The mailbox has sent to as many recipients in 24 hours as Exchange Online allows (10,000); it sends again once its count of the last 24 hours drops below that. " +
			"Keep the day's limit under Settings → Notifications → Mail server below the mail server's."
	case has("thread limit") || has("concurrent connections limit"):
		return "Exchange Online takes at most 3 connections at once for a mailbox, and another program, or another of EasyRMM's servers, is sending as it. Try again in a minute."
	case rateText(t):
		return "The mail server refused it for its rate. Keep the limits under Settings → Notifications → Mail server below the mail server's, and try again in a minute."
	}
	return ""
}

// rateText reports whether a reply's text, in lower case, refuses for rate.
func rateText(t string) bool {
	for _, s := range []string{"submissionquotaexceeded", "thread limit", "concurrent connections limit", "submission rate", "rate limit", "message rate",
		"too many messages", "throttled"} {
		if strings.Contains(t, s) {
			return true
		}
	}
	return false
}

// RateLimited reports whether the mail server refused for its rate, not
// for the message or the recipient (ADR-0053): such a refusal is not the
// recipient's, and is tried again later.
func (e *ReplyError) RateLimited() bool {
	t := strings.ToLower(e.Text)
	return rateText(t) && !strings.Contains(t, "sender throttled due to continuous")
}
