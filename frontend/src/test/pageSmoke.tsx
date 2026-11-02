/* A floor for a page that has no behavioural test yet.
 *
 * Mounting a page against a live-but-empty API answers one question: does it
 * render an honest empty state, or does it throw, render nothing, or put a
 * `NaN` / `undefined` / `Infinity` on a bank screen? That is not a claim about
 * correctness — a page can pass this and still misread a payload — but it is the
 * failure a bank notices first, and it is cheap enough to hold for every page.
 *
 * Assertions deliberately avoid the app shell: pages mount bare here, so a page
 * that does not use PageHead has no `.topbar`. */
import { expect } from "vitest";
import { act, waitFor } from "@testing-library/react";
import { renderWithProviders } from "./render";
import { mockFetch } from "./setup";

/** Text a page must never show: a number that was never computed, or a value
 *  that was never read. `undefined` in prose is the signature of a missing read. */
const NOT_A_FACT = /\b(?:NaN|undefined|Infinity)\b/;

export async function rendersAnHonestEmptyState(Page: React.ComponentType) {
  // every API read answers with `{}` — a live backend that has nothing to say
  mockFetch({ "/api/v1/*": {} });
  const errors: unknown[] = [];
  const onError = (event: ErrorEvent) => { errors.push(event.error ?? event.message); event.preventDefault(); };
  window.addEventListener("error", onError);
  try {
    let rendered: ReturnType<typeof renderWithProviders> | undefined;
    await act(async () => {
      rendered = renderWithProviders(<Page />);
    });
    const container = rendered!.container;
    await waitFor(
      () => expect(container.textContent?.trim().length ?? 0).toBeGreaterThan(0),
      { timeout: 5000 },
    );
    expect(errors, "uncaught error while rendering the page").toEqual([]);
    const body = container.textContent ?? "";
    // something structural, not just a stray character
    expect(container.querySelector("h1,h2,h3,table,.panel,.topbar")).not.toBeNull();
    expect(body).not.toMatch(NOT_A_FACT);
  } finally {
    window.removeEventListener("error", onError);
  }
}
