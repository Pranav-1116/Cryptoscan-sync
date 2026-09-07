/* Static internationalization (feature 23) — resource dictionaries only, no AI
   translation. English (LTR) and Arabic (RTL). The provider sets <html dir> and
   persists the choice; t(key) looks up the active dictionary with an English
   fallback so a missing key never renders blank. */
import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import en from "./en.json";
import ar from "./ar.json";

export type Lang = "en" | "ar";

const DICTS: Record<Lang, Record<string, string>> = { en, ar };
const DIR: Record<Lang, "ltr" | "rtl"> = { en: "ltr", ar: "rtl" };
const STORE_KEY = "zelnx_lang";

interface I18nCtx {
  lang: Lang;
  dir: "ltr" | "rtl";
  setLang: (l: Lang) => void;
  t: (key: string) => string;
}

const Ctx = createContext<I18nCtx>({
  lang: "en", dir: "ltr", setLang: () => {}, t: (k) => k,
});

function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORE_KEY);
    if (saved === "en" || saved === "ar") return saved;
  } catch { /* ignore */ }
  return "en";
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang);

  useEffect(() => {
    const dir = DIR[lang];
    document.documentElement.setAttribute("dir", dir);
    document.documentElement.setAttribute("lang", lang);
    try { localStorage.setItem(STORE_KEY, lang); } catch { /* ignore */ }
  }, [lang]);

  const value = useMemo<I18nCtx>(() => ({
    lang,
    dir: DIR[lang],
    setLang: setLangState,
    t: (key: string) => DICTS[lang][key] ?? DICTS.en[key] ?? key,
  }), [lang]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useI18n(): I18nCtx {
  return useContext(Ctx);
}

export function LanguageSwitcher() {
  const { lang, setLang, t } = useI18n();
  return (
    <span className="lang-switch" title={t("lang.label")}
      style={{ display: "inline-flex", border: "1px solid var(--line-strong)", borderRadius: 6, overflow: "hidden" }}>
      {(["en", "ar"] as Lang[]).map((l) => (
        <button key={l}
          onClick={() => setLang(l)}
          className="btn sm"
          style={{
            border: "none", borderRadius: 0,
            background: lang === l ? "var(--grad)" : "transparent",
            color: lang === l ? "#fff" : "var(--faint)",
            fontWeight: lang === l ? 700 : 500, padding: "3px 10px",
          }}>
          {l === "en" ? "EN" : "ع"}
        </button>
      ))}
    </span>
  );
}
