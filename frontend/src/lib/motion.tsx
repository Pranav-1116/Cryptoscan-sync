/* ─────────────────────────────────────────────────────────────────────
   ZELNX motion — one timing scale, one set of variants, one opt-out.

   Motion here is meant to answer "what just changed and where did it come
   from", not to decorate. Three rules it follows:

     1. Nothing moves far. Entrances travel 6-10px, because a long slide on
        a dense table reads as the data being unstable.
     2. Nothing loops except a genuinely live indicator. A console that
        breathes at rest competes with the status colours for attention.
     3. Every animation is off when the operator asked for that. Trading
        floors and accessibility settings both set prefers-reduced-motion,
        and a dealing-room screen that animates is a complaint.

   Durations are short on purpose: 0.18s for an element, 0.03s between
   staggered siblings. A twenty-row table finishes entering in ~0.8s, so
   the last row is not still arriving when someone goes to click it.
   ───────────────────────────────────────────────────────────────────── */

import React, { useEffect, useRef } from "react";
import { motion, useReducedMotion, type Variants } from "framer-motion";
import autoAnimate from "@formkit/auto-animate";

export const DUR = { fast: 0.14, base: 0.18, slow: 0.28 } as const;
/** A single easing for everything: slight ease-out, no bounce. Springy
 *  overshoot on an instrument reads as imprecision. */
export const EASE = [0.22, 0.61, 0.36, 1] as const;

export const fadeUp: Variants = {
  hidden: { opacity: 0, y: 8 },
  show: { opacity: 1, y: 0, transition: { duration: DUR.base, ease: EASE } },
};

export const fadeIn: Variants = {
  hidden: { opacity: 0 },
  show: { opacity: 1, transition: { duration: DUR.base, ease: EASE } },
};

/** Parent of a staggered group. Children use `fadeUp`. */
export const stagger = (step = 0.03, delay = 0): Variants => ({
  hidden: {},
  show: { transition: { staggerChildren: step, delayChildren: delay } },
});

/** True when motion is welcome. Wrap anything expensive in this. */
export function useMotionOK(): boolean {
  return !useReducedMotion();
}

/**
 * Entrance wrapper. Renders a plain element when motion is off, so there
 * is no hidden->show transition left half-applied and nothing can get
 * stuck at opacity 0 if an animation is interrupted mid-flight.
 */
export function Reveal({
  children,
  delay = 0,
  y = 8,
  className,
  style,
}: {
  children: React.ReactNode;
  delay?: number;
  y?: number;
  className?: string;
  style?: React.CSSProperties;
}) {
  const ok = useMotionOK();
  if (!ok) return <div className={className} style={style}>{children}</div>;
  return (
    <motion.div
      className={className}
      style={style}
      initial={{ opacity: 0, y }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: DUR.base, ease: EASE, delay }}
    >
      {children}
    </motion.div>
  );
}

/**
 * Count a metric up to its value.
 *
 * Deliberately NOT a generic number animation: it animates only when the
 * value is a finite number, it always lands exactly on the target rather
 * than on a rounded interpolation, and it skips the animation entirely
 * for a value that changes while it is still running (a live KPI that
 * re-animates on every poll is a distraction, not an affordance).
 */
export function CountUp({
  value,
  duration = 0.5,
  format = (n: number) => n.toLocaleString(),
}: {
  value: number;
  duration?: number;
  format?: (n: number) => string;
}) {
  const ok = useMotionOK();
  const [shown, setShown] = React.useState(() => (ok ? 0 : value));
  const done = useRef(false);

  useEffect(() => {
    // Fail to the real figure, never to the placeholder. If motion is off,
    // the value is not finite, or the host has no rAF (SSR, some test and
    // kiosk runtimes), show the number immediately -- a KPI frozen at 0
    // because an animation never started would be a lie about the estate.
    if (
      !ok ||
      done.current ||
      !Number.isFinite(value) ||
      typeof requestAnimationFrame !== "function"
    ) {
      setShown(value);
      return;
    }
    if (value === 0) { setShown(0); done.current = true; return; }
    let raf = 0;
    const t0 = performance.now();
    const ms = duration * 1000;
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / ms);
      // ease-out cubic: fast first, settles onto the real figure
      const eased = 1 - Math.pow(1 - p, 3);
      setShown(p === 1 ? value : Math.round(value * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
      else done.current = true;
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, ok, duration]);

  return <>{format(shown)}</>;
}

/**
 * Attach FormKit auto-animate to a list/table body so rows that are added,
 * removed or reordered move instead of jumping. Returns a ref to spread
 * onto the container element.
 */
export function useAutoAnimate<T extends HTMLElement>() {
  const ref = useRef<T>(null);
  const ok = useMotionOK();
  useEffect(() => {
    // auto-animate reads window.matchMedia on attach to pick up the OS
    // reduced-motion setting. jsdom does not implement it, and neither do
    // some embedded/kiosk browsers, where an unguarded call throws
    // "window.matchMedia is not a function" and takes the whole page down
    // with it. Motion is a nicety; never let it break a render.
    if (!ref.current || !ok) return;
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    try {
      autoAnimate(ref.current, { duration: 160, easing: "ease-out" });
    } catch {
      /* animation is optional; a table that does not glide still works */
    }
  }, [ok]);
  return ref;
}

/* ── cryptography-flavoured reveal ───────────────────────────────────
   A heading resolves out of ciphertext: each character cycles through
   hex digits before settling on its real glyph, left to right, like a
   block decrypting. It is the one piece of decorative motion in the
   product, and it earns its place by being about the subject — this is
   a cryptography console, so "plaintext emerging from ciphertext" is
   the house metaphor rather than a generic fade.

   Constraints that keep it from becoming a gimmick:
     - It runs once per mount, never on a re-render or a data poll.
     - Only letters and digits scramble. Spaces, punctuation and the
       separators in "CBOM · Cryptography" hold still, so the heading
       keeps its shape and the layout never reflows mid-animation.
     - It is capped at ~550ms regardless of length, so a long title does
       not keep an operator waiting to read where they are.
     - With reduced motion it renders the plain string immediately.
   ──────────────────────────────────────────────────────────────────── */
const CIPHER_GLYPHS = "0123456789ABCDEF";

export function DecryptText({
  text,
  className,
  durationMs = 550,
}: {
  text: string;
  className?: string;
  durationMs?: number;
}) {
  const ok = useMotionOK();
  // Starts as the real text: that way the first paint is correct, the
  // element measures at its true width, and a no-JS / no-rAF host shows
  // plaintext rather than an empty heading.
  const [out, setOut] = React.useState(text);
  const host = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    if (!ok || typeof requestAnimationFrame !== "function") { setOut(text); return; }
    // Pin the box to the plaintext width before scrambling. Hex digits
    // are not the same width as letters in a proportional font, so an
    // unpinned heading twitches and shoves the toolbar beside it. Width
    // is measured while the real text is still rendered.
    const el = host.current;
    if (el && typeof el.getBoundingClientRect === "function") {
      const w = el.getBoundingClientRect().width;
      if (w > 0) el.style.minWidth = `${Math.ceil(w)}px`;
    }
    const chars = Array.from(text);
    const scrambles = chars.map((c) => /[A-Za-z0-9]/.test(c));
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / durationMs);
      // How far the "decrypted" boundary has swept across the string.
      const settled = p * chars.length;
      setOut(
        chars
          .map((c, i) => {
            if (!scrambles[i] || i < settled) return c;
            return CIPHER_GLYPHS[(Math.random() * CIPHER_GLYPHS.length) | 0];
          })
          .join(""),
      );
      if (p < 1) raf = requestAnimationFrame(tick);
      else setOut(text);
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); setOut(text); };
  }, [text, ok, durationMs]);

  // One text node only. An earlier version painted the animation over a
  // hidden copy of the string to hold the width, which put the title in
  // the DOM twice -- enough to break getByText and to show up twice to
  // anything scraping the page. The measured minWidth does the same job
  // without duplicating content.
  //
  // aria-label carries the plaintext, so assistive tech announces the
  // real title rather than whatever ciphertext is on screen this frame.
  if (!ok) return <span className={className}>{text}</span>;
  return (
    <span
      ref={host}
      className={className}
      style={{ display: "inline-block", whiteSpace: "pre" }}
      aria-label={text}
    >
      {out}
    </span>
  );
}

/** Staggered group helper: <StaggerGroup> wrapping <StaggerItem> children. */
export function StaggerGroup({
  children,
  step = 0.03,
  delay = 0,
  className,
  style,
}: {
  children: React.ReactNode;
  step?: number;
  delay?: number;
  className?: string;
  style?: React.CSSProperties;
}) {
  const ok = useMotionOK();
  if (!ok) return <div className={className} style={style}>{children}</div>;
  return (
    <motion.div
      className={className}
      style={style}
      variants={stagger(step, delay)}
      initial="hidden"
      animate="show"
    >
      {children}
    </motion.div>
  );
}

export function StaggerItem({
  children,
  className,
  style,
}: {
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}) {
  const ok = useMotionOK();
  if (!ok) return <div className={className} style={style}>{children}</div>;
  return (
    <motion.div className={className} style={style} variants={fadeUp}>
      {children}
    </motion.div>
  );
}
