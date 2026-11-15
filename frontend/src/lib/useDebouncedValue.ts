/* useDebouncedValue — the shared debounce primitive.
 *
 * "Debounced search: prevents a database/API request for every keystroke."
 * Every API-bound search input debounces through this hook so a burst of
 * keystrokes becomes one request. Client-side-only filters may skip it —
 * they hit no API — but anything that will fetch MUST pass through here.
 */

import { useEffect, useState } from "react";

export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}
