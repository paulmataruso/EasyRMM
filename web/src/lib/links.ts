// Links built from what people type into the customer record: an email address, a phone number, a website. Each
// is made safe here, not where it is shown, so that no page links a value as typed.

/**
 * An input for an email address in the customer record. Text with an email keyboard, not type="email": the
 * browser's check refuses letters beyond ASCII before the @, as in zoë@example.com, which the server takes. The
 * server alone judges an address, and its message shows under the field.
 */
export const EMAIL_INPUT = { type: "text", inputMode: "email", autoCapitalize: "none", spellCheck: false } as const;

/**
 * A mailto: link to one address. The server accepts only plain addresses, but each part is percent-encoded all
 * the same, so that a ? or & can never start a header such as bcc (RFC 6068).
 */
export function mailtoHref(address: string): string {
  const at = address.lastIndexOf("@");
  if (at < 0) return `mailto:${encodeURIComponent(address)}`;
  return `mailto:${encodeURIComponent(address.slice(0, at))}@${encodeURIComponent(address.slice(at + 1))}`;
}

/** A tel: link: the digits, and a leading + when there is one. */
export function telHref(phone: string): string {
  const digits = phone.replace(/\D/g, "");
  return `tel:${phone.trimStart().startsWith("+") ? "+" : ""}${digits}`;
}

/** The address to link a website to: an http or https URL only, else null and the site is shown as text. */
export function websiteHref(website: string): string | null {
  try {
    const url = new URL(website);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}
