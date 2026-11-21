import type { MailProblem } from "../../api/types";

/** Why a link came back to whoever sent it instead of going by email, and what to do. */
export function whyNotEmailed(problem: MailProblem | undefined, email: string): string {
  return problem === "not_sent"
    ? `The mail server did not take the message, so send it to ${email} yourself.`
    : `EasyRMM has no mail server, so send it to ${email} yourself.`;
}
