/** Leaves the console for another address (the identity provider's sign-in). A function of its own so tests can replace it. */
export function leaveFor(url: string): void {
  window.location.assign(url);
}
