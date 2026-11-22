import type { MailProblem } from "../../api/types";

/** Why a link came back to whoever sent it instead of going by email, and what to do. reason is the limit that stopped it, when one did. */
export function whyNotEmailed(problem: MailProblem | undefined, email: string, reason?: string): string {
  if (reason) return `It was not emailed: ${reason} Send it to ${email} yourself.`;
  return problem === "not_sent"
    ? `The mail server did not take the message, so send it to ${email} yourself.`
    : `EasyRMM has no mail server, so send it to ${email} yourself.`;
}
