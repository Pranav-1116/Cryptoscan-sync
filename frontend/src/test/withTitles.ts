/** Visible text plus every hover title inside `el`, whitespace-normalised.
 *  Long captions are shown shortened with the full sentence on hover, so a
 *  test asserting the full disclosure reads both. */
export function withTitles(el: Element | null | undefined): string {
  if (!el) return "";
  const titles = [el, ...Array.from(el.querySelectorAll("[title]"))]
    .map((n) => n.getAttribute("title") || "").filter(Boolean);
  return [el.textContent || "", ...titles].join(" ").replace(/\s+/g, " ");
}
