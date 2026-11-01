/** Private browser context changes invalidate evidence, drafts and downloads.
 * This is a client display fence, never an authorization or write-rollback claim.
 */
export function watchPrivateScope(invalidate: () => void): () => void {
  const storage = (event: StorageEvent) => {
    try { if (event.storageArea && event.storageArea !== window.localStorage) return; }
    catch { invalidate(); return; }
    if (event.key === null || ["cryptoscan_tenant", "zelinx_signed_in", "zelinx_roles", "zelinx_user"].includes(event.key)) invalidate();
  };
  const visible = () => { if (!document.hidden) invalidate(); };
  const restored = (event: PageTransitionEvent) => { if (event.persisted) invalidate(); };
  window.addEventListener("zelinx:tenant", invalidate);
  window.addEventListener("zelinx:auth", invalidate);
  window.addEventListener("storage", storage);
  window.addEventListener("pageshow", restored);
  document.addEventListener("visibilitychange", visible);
  return () => {
    window.removeEventListener("zelinx:tenant", invalidate);
    window.removeEventListener("zelinx:auth", invalidate);
    window.removeEventListener("storage", storage);
    window.removeEventListener("pageshow", restored);
    document.removeEventListener("visibilitychange", visible);
  };
}
