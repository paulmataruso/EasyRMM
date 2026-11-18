/** Loads a path from the server in this tab, leaving the console: for links the server answers, not the console. */
export function leaveFor(path: string): void {
  window.location.replace(path);
}
