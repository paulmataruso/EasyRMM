import { useEffect, useState } from "react";

/** A value that follows `value` after it has held still for `ms`. */
export function useDebounced<T>(value: T, ms: number): T {
  const [held, setHeld] = useState(value);
  useEffect(() => {
    if (value === held) return;
    const t = setTimeout(() => setHeld(value), ms);
    return () => clearTimeout(t);
  }, [value, held, ms]);
  return held;
}
