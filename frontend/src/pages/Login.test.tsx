import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nProvider } from "../i18n/I18n";
import en from "../i18n/en.json";
import ar from "../i18n/ar.json";
import Login from "./Login";

const reducedMotion = vi.hoisted(() => ({ current: false }));
vi.mock("framer-motion", async (importOriginal) => ({
  ...(await importOriginal<typeof import("framer-motion")>()),
  useReducedMotion: () => reducedMotion.current,
}));

function renderLogin() {
  return render(<I18nProvider><MemoryRouter><Login /></MemoryRouter></I18nProvider>);
}

beforeEach(() => { reducedMotion.current = false; });
afterEach(() => { vi.unstubAllGlobals(); });

describe("login brand reveal", () => {
  it("paints readable plaintext first, exposes it to assistive tech, and leaves sign-in controls usable", async () => {
    const frames: FrameRequestCallback[] = [];
    vi.stubGlobal("requestAnimationFrame", vi.fn((callback: FrameRequestCallback) => {
      frames.push(callback);
      return frames.length;
    }));
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
    vi.spyOn(performance, "now").mockReturnValue(0);

    renderLogin();
    const cue = screen.getByText(en["app.title"]);
    expect(cue).toHaveAttribute("aria-label", en["app.title"]);
    expect(cue.textContent).toBe(en["app.title"]);
    expect(screen.getByRole("heading", { name: en["login.heroTitle"] })).toBeInTheDocument();
    expect(screen.getByLabelText(en["login.username"])).toHaveFocus();
    expect(screen.getByLabelText(en["login.password"])).toBeInTheDocument();
    expect(screen.getByRole("button", { name: en["login.signIn"] })).toBeDisabled();
    await screen.findByText(en["app.banner.offline"]);

    act(() => { frames.shift()?.(100); });
    expect(cue.textContent).not.toBe(en["app.title"]);
    expect(cue).toHaveAttribute("aria-label", en["app.title"]);

    act(() => { frames.shift()?.(551); });
    expect(cue.textContent).toBe(en["app.title"]);
    expect(frames).toHaveLength(0);

    fireEvent.change(screen.getByLabelText(en["login.username"]), { target: { value: "analyst" } });
    expect(frames).toHaveLength(0);
    expect(cue.textContent).toBe(en["app.title"]);
  });

  it("renders static translated plaintext in reduced motion, including after an RTL switch", async () => {
    reducedMotion.current = true;
    const raf = vi.fn();
    vi.stubGlobal("requestAnimationFrame", raf);

    renderLogin();
    expect(screen.getByText(en["app.title"])).toBeInTheDocument();
    expect(raf).not.toHaveBeenCalled();
    await screen.findByText(en["app.banner.offline"]);

    fireEvent.click(screen.getByRole("button", { name: "ع" }));
    expect(document.documentElement).toHaveAttribute("dir", "rtl");
    expect(screen.getByText(ar["app.title"])).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: ar["login.heroTitle"] })).toBeInTheDocument();
    expect(screen.getByLabelText(ar["login.username"])).toBeInTheDocument();
    expect(raf).not.toHaveBeenCalled();
  });
});
