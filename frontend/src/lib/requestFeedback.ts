/** Safe, body-independent HTTP feedback. Never echo server detail or exception
 * messages. A rejected validation is not an ambiguous transport failure; neither
 * should erase a useful draft or automatically replay a mutation.
 */
export function readFailure(status: number): string {
  const category = status === 401 ? "Session expired or authentication required"
    : status === 403 ? "Access refused" : status >= 500 ? "Service unavailable" : "Read refused";
  return `${category} (HTTP ${status})`;
}
export function writeFailure(status?: number): string {
  if (status === 400 || status === 422)
    return `Validation rejected (HTTP ${status}). Draft retained; correct the schema fields before submitting again.`;
  if (status === 409)
    return "State or revision conflict (HTTP 409). Draft retained; reconcile current history and authority before changing the expected revision. Do not blindly retry.";
  if (status === 401 || status === 403)
    return `${readFailure(status)}. Draft retained in this context; re-establish authority and reconcile history before retrying.`;
  return `Action outcome not confirmed${status === undefined ? "" : ` (HTTP ${status})`}. Draft retained; reconcile current history before retrying. The server may already have retained the write.`;
}
