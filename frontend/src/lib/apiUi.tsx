/* React glue for the API bridge — the hook and the source badge live in
   a .tsx module (they render JSX). */

import { useEffect, useState } from "react";
import { ApiResult, ApiSource } from "./api.js";

export function useApi<T>(fn: () => Promise<ApiResult<T>>, deps: unknown[] = []) {
  const [result, setResult] = useState<ApiResult<T>>({ source: "demo", data: null });
  const [running, setRunning] = useState(false);

  const run = async () => {
    setRunning(true);
    const res = await fn();
    setResult(res);
    setRunning(false);
    return res;
  };

  useEffect(() => {
    // eslint-disable-next-line react-hooks/exhaustive-deps
    void run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  return { ...result, running, run };
}

export function LiveBadge({ source, label }: { source: ApiSource; label?: string }) {
  return source === "live" ? (
    <span className="badge green"><span className="dot" /> {label || "LIVE API DATA"}</span>
  ) : (
    <span className="badge amber"><span className="dot" /> {label || "DEMO DATA"}</span>
  );
}
