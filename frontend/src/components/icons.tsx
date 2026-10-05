/* ─────────────────────────────────────────────────────────────────────
   ZELNX iconography — one set, one size scale, one weight.

   The console previously drew icons three different ways on the same
   screen: Phosphor components in the sidebar nav, emoji (🔐 🏢 🌐 🔩 👤)
   in search/admin/tenant surfaces, and bare glyphs (✕ ▼ ✓ ⚠ » «) in
   buttons and status text. Emoji are the worst of the three: they render
   as full-colour vendor artwork that ignores --text and --dim entirely,
   they shift baseline against the type, and they look different on every
   OS — so a screenshot taken on one machine does not match another.

   Mixing all three is what makes an otherwise disciplined interface read
   as improvised. Everything below resolves to the same Phosphor set at
   the same optical size, inheriting currentColor so the status tokens in
   global.css keep their single meaning.

   Import from here, never from @phosphor-icons/react directly, so the
   size/weight scale stays enforceable in one place.
   ───────────────────────────────────────────────────────────────────── */

import {
  Buildings,
  Calendar,
  CaretDown,
  CaretLeft,
  CaretRight,
  CaretUp,
  Check,
  CircleDashed,
  CheckCircle,
  Circle,
  Clock,
  Cloud,
  Cube,
  Certificate,
  Code,
  Cpu,
  Gear,
  GlobeHemisphereWest,
  Info,
  Heartbeat,
  Key,
  Keyboard,
  Lightning,
  LockKey,
  MagnifyingGlass,
  Minus,
  Moon,
  Nut,
  Play,
  Broadcast,
  Pulse,
  ShieldCheck,
  Stack,
  Sun,
  Target,
  TrendDown,
  TrendUp,
  User,
  Warning,
  X,
  XCircle,
  type Icon,
} from "@phosphor-icons/react";

/** Optical sizes. An icon sits beside text, so these track the type scale
 *  rather than being round numbers: 14 is inline with 12.5px body copy. */
export const ICON_SM = 13;
export const ICON_MD = 14;
export const ICON_LG = 16;

/** Status and control. Named for the job, not the picture, so a call site
 *  reads `<IconFail />` and not `<XCircle />` — the glyph can change
 *  without every page having to agree about what X meant. */
export const IconOk = Check;
export const IconPass = CheckCircle;
export const IconFail = XCircle;
export const IconClose = X;
export const IconWarn = Warning;
export const IconNeutral = Circle;
export const IconRunning = Play;
export const IconCaretDown = CaretDown;
export const IconCaretUp = CaretUp;
export const IconCaretLeft = CaretLeft;
export const IconCaretRight = CaretRight;

/** Domain. These replace the emoji that stood in for each estate domain. */
export const IconCrypto = Key;
export const IconSecret = LockKey;
export const IconNetwork = GlobeHemisphereWest;
export const IconHardware = Cpu;
export const IconComponent = Nut;
export const IconCloud = Cloud;
export const IconTenant = Buildings;
export const IconUser = User;
export const IconSecurity = ShieldCheck;
export const IconClock = Clock;
export const IconCalendar = Calendar;
export const IconHealth = Heartbeat;
export const IconLive = Pulse;
export const IconAccelerator = Lightning;
export const IconTarget = Target;
export const IconEstate = Stack;
export const IconLight = Sun;
export const IconDark = Moon;
export const IconSettings = Gear;
export const IconInfo = Info;
export const IconCode = Code;
export const IconCertificate = Certificate;
export const IconContainer = Cube;
export const IconKeyboard = Keyboard;
export const IconSearch = MagnifyingGlass;
export const IconSatellite = Broadcast;
export const IconTrendUp = TrendUp;
export const IconTrendDown = TrendDown;
export const IconTrendFlat = Minus;
export const IconRadioOn = CheckCircle;
export const IconRadioOff = CircleDashed;

export type { Icon };

/**
 * Brand mark. Was the glyph ◈ on a `--grad` background with a
 * `--glow-cyan` box-shadow -- the two treatments global.css explicitly
 * rules out ("No gradient and no glow. Both read as ornament on an
 * instrument"). Drawn as a flat SVG so it is one shape at any size
 * instead of a font-dependent character.
 */
export function BrandMark({ size = 30 }: { size?: number }) {
  return (
    <span className="brandmark" style={{ width: size, height: size }} aria-hidden="true">
      <svg viewBox="0 0 24 24" width={size * 0.55} height={size * 0.55} fill="none">
        <path d="M12 2.5 21.5 12 12 21.5 2.5 12z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
        <path d="M12 8.5 15.5 12 12 15.5 8.5 12z" fill="currentColor" />
      </svg>
    </span>
  );
}

/**
 * The one place a boolean becomes a mark. Dozens of call sites wrote
 * `{ok ? "✓" : "·"}` or `{ok ? "✓ " : "✕ "}` inline, each picking its own
 * character and colour; a few used "✗" where their neighbour used "✕".
 */
export function StatusMark({
  ok,
  size = ICON_MD,
  muted = false,
}: {
  ok: boolean | null | undefined;
  size?: number;
  muted?: boolean;
}) {
  if (ok === null || ok === undefined) {
    // Unknown is an absence, not a failure: global.css reserves --slate
    // for exactly this and the shape stays hollow to say "nothing known".
    return <IconNeutral size={size} weight="bold" color="var(--slate)" aria-label="unknown" />;
  }
  if (ok) {
    return <IconOk size={size} weight="bold" color={muted ? "currentColor" : "var(--green)"} aria-label="yes" />;
  }
  return <IconClose size={size} weight="bold" color={muted ? "currentColor" : "var(--red)"} aria-label="no" />;
}
