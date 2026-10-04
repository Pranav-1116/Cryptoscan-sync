import React, { useState } from "react";
import { downloadAuthenticatedResource } from "../lib/api.js";

/**
 * Download control for API resources that must not be exposed as unauthenticated
 * anchor navigations. It keeps the response on the tenantFetch path and shows
 * a bounded failure instead of implying that an unauthorized export succeeded.
 */
export default function AuthenticatedDownload({
  path,
  filename,
  children,
  className,
  style,
}: {
  path: string;
  filename: string;
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const download = async () => {
    setBusy(true);
    setError(null);
    try {
      await downloadAuthenticatedResource(path, filename);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button type="button" className={className} style={style} onClick={() => void download()} disabled={busy}>
        {busy ? "Preparing…" : children}
      </button>
      {error && <span role="alert" style={{ color: "var(--amber)", fontSize: 11 }}>unavailable: {error}</span>}
    </>
  );
}
