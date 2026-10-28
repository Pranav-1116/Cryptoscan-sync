import { useCallback, useEffect, useRef, useState } from "react";
import type { ApiResult } from "./api";
import { usePrivateScopeCurrent } from "../components/PrivateScope";

/**
 * One read, fenced against a scope change.
 *
 * The assurance screens are read-only: every one of them asks the control plane
 * for a payload and renders exactly that payload. There is no retry that hides a
 * failure, no cached previous success and no client-side derived metric — a failed
 * read produces an error line, not the last good table.
 */
export function useAssuranceRead<T>() {
  const scopeCurrent = usePrivateScopeCurrent();
  const generation = useRef(0);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [source, setSource] = useState<"live" | "offline" | "">("");

  useEffect(() => () => { generation.current++; }, []);

  const clear = useCallback(() => {
    generation.current++;
    setData(null);
    setError("");
    setSource("");
  }, []);

  const run = useCallback(async (read: () => Promise<ApiResult<T>>, what: string) => {
    const mine = ++generation.current;
    setBusy(true);
    setError("");
    setData(null);
    setSource("");
    try {
      const result = await read();
      if (!scopeCurrent() || mine !== generation.current) return;
      if (result.ok !== true || result.data == null) {
        setError(`${what} unavailable (${result.error || "no payload"}); no cached success substituted.`);
        return;
      }
      setData(result.data);
      setSource(result.source);
    } catch (e) {
      if (scopeCurrent() && mine === generation.current) {
        setError(`${what} failed: ${e instanceof Error ? e.message : String(e)}; nothing was inferred.`);
      }
    } finally {
      if (mine === generation.current) setBusy(false);
    }
  }, [scopeCurrent]);

  return { data, error, busy, source, run, clear };
}

export const idInputStyle = {
  boxSizing: "border-box" as const,
  minWidth: 0,
  width: "100%",
  padding: 8,
  color: "inherit",
  background: "var(--surface-2, #171f2c)",
  border: "1px solid #526074",
  borderRadius: 4,
};

export function shortSha(value: string | null | undefined): string {
  if (!value) return "—";
  return value.length > 16 ? `${value.slice(0, 12)}…` : value;
}

export function Json({ value }: { value: unknown }) {
  return <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", maxHeight: 420, overflow: "auto" }}>
    {JSON.stringify(value, null, 2)}
  </pre>;
}
