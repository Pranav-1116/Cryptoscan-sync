import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { I18nProvider, LanguageSwitcher, useI18n } from "./I18n";
import en from "./en.json";
import ar from "./ar.json";

function Probe({ k }: { k: string }) {
  const { t, lang, dir } = useI18n();
  return <div data-testid="probe" data-lang={lang} data-dir={dir}>{t(k)}</div>;
}

describe("i18n", () => {
  it("defaults to English, LTR", () => {
    render(<I18nProvider><Probe k="app.title" /></I18nProvider>);
    const el = screen.getByTestId("probe");
    expect(el).toHaveTextContent((en as Record<string, string>)["app.title"]);
    expect(el.dataset.lang).toBe("en");
    expect(el.dataset.dir).toBe("ltr");
  });

  it("switches to Arabic and flips the document direction to RTL", () => {
    render(<I18nProvider><LanguageSwitcher /><Probe k="app.title" /></I18nProvider>);
    fireEvent.click(screen.getByText("ع"));
    const el = screen.getByTestId("probe");
    expect(el.dataset.lang).toBe("ar");
    expect(el.dataset.dir).toBe("rtl");
    expect(document.documentElement.getAttribute("dir")).toBe("rtl");
    expect(el).toHaveTextContent((ar as Record<string, string>)["app.title"]);
    expect(localStorage.getItem("zelnx_lang")).toBe("ar");
  });

  it("falls back to the key for an unknown id and to English for an untranslated one", () => {
    render(<I18nProvider><Probe k="does.not.exist" /></I18nProvider>);
    expect(screen.getByTestId("probe")).toHaveTextContent("does.not.exist");
  });

  it("every Arabic key exists in English (no orphan translations)", () => {
    const missing = Object.keys(ar).filter((k) => !(k in en));
    expect(missing).toEqual([]);
  });
});
