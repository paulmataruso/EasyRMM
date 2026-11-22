// Links built from what people type into the customer record: an email address, a phone number, a website. Each
// is made safe here, not where it is shown, so that no page links a value as typed.

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
