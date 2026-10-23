import React, { createContext, useContext, useEffect, useRef, useState } from "react";
import { watchPrivateScope } from "../lib/privateScope";

const CurrentScope = createContext<() => boolean>(() => true);
export const usePrivateScopeCurrent = () => useContext(CurrentScope);

/** Remount private state, and fence callbacks synchronously before React flushes.
 * Visible resume / BFCache restoration require a fresh server read. Unsubmitted
 * drafts are deliberately discarded; no request is automatically replayed.
 */
export default function PrivateScope({ children }: { children: React.ReactNode }) {
  const generation = useRef(0);
  const active = useRef(true);
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    active.current = true;
    const stop = watchPrivateScope(() => { generation.current++; setEpoch(generation.current); });
    return () => { active.current = false; stop(); };
  }, []);
  const current = () => active.current && generation.current === epoch;
  return <CurrentScope.Provider value={current}>
    {epoch > 0 && <p role="status">Session, estate or resumed-tab context changed. Private evidence and unsubmitted drafts were cleared; reconcile current history before retrying a write.</p>}
    <React.Fragment key={epoch}>{children}</React.Fragment>
  </CurrentScope.Provider>;
}
