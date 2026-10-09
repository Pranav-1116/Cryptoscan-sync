# 06_FRONTEND_AUDIT.md
## ZELNX CryptoScan — Frontend Deep Audit

**Generated:** 2026-09-20  
**Method:** Source code inspection of all 71 pages, components, hooks, and API layer  
**Scope:** React 18 + TypeScript + Vite — actual implementation vs. enterprise UX requirements

---

## 1. FRONTEND ARCHITECTURE

### 1.1 Technology Stack
| Component | Version | Purpose |
|-----------|---------|---------|
| React | 18.3.1 | UI framework |
| TypeScript | 5.6.3 | Type safety |
| Vite | 5.4.11 | Build tool + dev server |
| React Router | 7.18.4 | Routing (lazy-loaded) |
| Framer Motion | 14.0.0 | Page transitions |
| Phosphor Icons | 2.1.10 | Icon system |
| @formkit/auto-animate | 0.10.0 | List animations |
| Vitest | 2.1.9 | Testing |
| jsdom | 30.1.1 | Test environment |

### 1.2 Route Structure (`App.tsx`)
- **Public routes (no auth):** `/login`, `/register`, `/reset-password`, `/invite-accept`
- **Protected routes (RequireAuth + RealtimeProvider + Layout):** 71 lazy-loaded pages
- **Fallback:** Unknown routes → `/command-center`
- **Code splitting:** One chunk per page via `React.lazy()`

### 1.3 State Management
- **Server state:** Custom hooks (`usePollingApi`, `useLive`, `useRealtime`) — no React Query/SWR
- **Client state:** React `useState`/`useReducer` per component
- **Auth state:** `AuthProvider` context with session persistence
- **Realtime:** SSE/WebSocket via `RealtimeProvider` + `useRealtime()`

---

## 2. PAGE INVENTORY & IMPLEMENTATION STATUS

### 2.1 Core Dashboard Pages
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| CommandCenter | `CommandCenter.tsx` | 800+ | `/live-scan/inventory`, `/control/agents`, `/events/recent`, `/stats/summary`, `/deliveries`, `/live-scan/status`, `/live/alerts`, `/live/bom`, `/live/drift` | ✅ Real API |
| Assets | `Assets.tsx` | 13.7K | `/assets`, `/cbom/search` | ✅ Real API |
| CryptoAssets | `CryptoAssets.tsx` | 5.4K | `/crypto/assets` | ✅ Real API |
| CryptoAssurance | `CryptoAssurance.tsx` | 18.4K | `/crypto/assurance` | ✅ Real API |
| Findings | `Findings.tsx` | 17.4K | `/findings` | ✅ Real API |
| Evidence | `Evidence.tsx` | 12.0K | `/evidence` | ✅ Real API |

### 2.2 CBOM/HBOM/Graph Pages
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| Cbom | `Cbom.tsx` | 15.0K | `/cbom`, `/cbom/portfolio`, `/cbom/system/{id}`, `/cbom/scan/{id}` | ✅ Real API |
| Hbom | `Hbom.tsx` | 1.9K | **NONE** | ❌ **STUB** — "HBOM status UNKNOWN — no HBOM evidence" |
| Graph | `Graph.tsx` | 11.2K | `/graph`, `/graph/blast-radius`, `/graph/impact` | ✅ Real API |
| DependencyGraph | `DependencyGraph.tsx` | 14.5K | `/graph` | ✅ Real API |
| DigitalTwin | `DigitalTwin.tsx` | 19.9K | `/digital-twin` | ✅ Real API |

### 2.3 Discovery & Inventory Pages
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| Network | `Network.tsx` | 17.2K | `/network`, `/network-scans` | ✅ Real API |
| Cloud | `Cloud.tsx` | 14.6K | `/cloud`, `/cloud-scans` | ✅ Real API |
| Container | `Container.tsx` | 6.7K | `/container`, `/container-scans` | ✅ Real API |
| Certificates | `Certificates.tsx` | 13.7K | `/certificates` | ✅ Real API |
| Hardware | `Hardware.tsx` | 11.4K | `/hardware` | ✅ Real API |
| Scanners | `Scanners.tsx` | 14.1K | `/scanners`, `/live-scanners` | ✅ Real API |
| LiveScanners | `LiveScanners.tsx` | 13.4K | `/live-scan/status` | ✅ Real API |
| LiveAssetIntelligence | `LiveAssetIntelligence.tsx` | 58.9K | `/live-asset-intelligence` | ✅ Real API |
| LiveEnvironment | `LiveEnvironment.tsx` | 12.2K | `/live-environment` | ✅ Real API |

### 2.4 Risk, Compliance, PQC Pages
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| Risk | `Risk.tsx` | 3.7K | `/risk` | ✅ Real API |
| Drift | `Drift.tsx` | 11.7K | `/drift`, `/drift/digest` | ✅ Real API |
| Compliance | `Compliance.tsx` | 8.8K | `/compliance` | ✅ Real API |
| Pqc | `Pqc.tsx` | 10.5K | `/quantum`, `/pqc-map` | ✅ Real API |
| PqcMap | `PqcMap.tsx` | 4.6K | `/pqc-map` | ✅ Real API |
| Agility | `Agility.tsx` | 3.9K | `/agility` | ✅ Real API |
| Migration | `Migration.tsx` | 8.4K | `/migration` | ✅ Real API |
| WhatIf | `WhatIf.tsx` | 10.3K | `/crypto/simulate` | ✅ Real API |

### 2.5 DevSecOps & Operations
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| DevSecOps | `DevSecOps.tsx` | 93.8K | `/container/scan`, `/k8s/scan`, `/cloud/posture`, `/sbom/*`, `/binary/*` | ✅ Real API |
| Automation | `Automation.tsx` | 16.6K | `/automation` | ✅ Real API |
| ControlPlane | `ControlPlane.tsx` | 47.2K | `/control-plane` | ✅ Real API |
| SecurityCenter | `SecurityCenter.tsx` | 20.1K | `/security` | ✅ Real API |
| SecurityIntelligence | `SecurityIntelligence.tsx` | 15.4K | `/security-intelligence` | ✅ Real API |

### 2.6 Specialized Domains
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| BankingRegulatory | `BankingRegulatory.tsx` | 15.6K | `/banking` | ✅ Real API |
| Telecom | `Telecom.tsx` | 19.3K | `/telecom` | ✅ Real API |
| PaymentCrypto | `PaymentCrypto.tsx` | 20.2K | `/payment-crypto` | ✅ Real API |
| OT / OTSafety | `OT.tsx` / `OTSafety.tsx` | 2.2K / 8.7K | `/ot`, `/ot-safety` | ✅ Real API |
| Vendor / VendorDueDiligence | `Vendor.tsx` / `VendorDueDiligence.tsx` | 7.2K / 14.7K | `/vendor`, `/vendor-due-diligence` | ✅ Real API |

### 2.7 Admin & Settings
| Page | File | Lines | Data Source | Status |
|------|------|-------|-------------|--------|
| Admin | `Admin.tsx` | 4.3K | `/admin`, `/auth/users` | ✅ Real API |
| Settings | `Settings.tsx` | 8.2K | `/settings` | ✅ Real API |
| Organization | `Organization.tsx` | 6.1K | `/organization` | ✅ Real API |
| Tenancy | `Tenancy.tsx` | 13.6K | `/tenancy` | ✅ Real API |
| Identity | `Identity.tsx` | 15.1K | `/identity` | ✅ Real API |

---

## 3. DATA INTEGRATION PATTERNS

### 3.1 API Layer (`frontend/src/lib/api.js`)
```typescript
// Pattern: async function returning ApiResult<T>
export async function apiCbomForSystem(systemId: string): Promise<ApiResult<CbomResponse>> {
  return fetchJson(`/api/v1/cbom/system/${systemId}`);
}

// ApiResult discriminated union:
type ApiResult<T> = 
  | { source: "live"; ok: true; data: T }
  | { source: "live"; ok: false; data: null; error: string }
  | { source: "offline"; ok: false; data: null; error: string };
```

### 3.2 Data Fetching Hooks
| Hook | File | Behavior |
|------|------|----------|
| `usePollingApi` | `apiUi.jsx` | Polls endpoint at interval; returns `{data, source, loading, error, run()}` |
| `useLive` | `useLive.js` | Wrapper for live endpoints; manual `reload()` |
| `useRealtime` | `realtime.js` | SSE/WebSocket event stream; `events[]` array |
| `useRealtimeRefresh` | `realtime.js` | Triggers refetch on relevant realtime events |

### 3.3 "Zero Until Real Data" Pattern
```tsx
// CommandCenter.tsx — every KPI shows "UNKNOWN" not zero
const g = { pqcReadyPct: 0, ... }; // defaults
// Only populated when liveStats.source === "live" && liveBom.source === "live"
const pqcObserved = liveStats.source === "live" && liveBom.source === "live" && typeof cov.coverage_pct === "number";
```
**Result:** Dashboards honestly show "UNKNOWN — no live evidence" instead of fake zeros.

---

## 4. COMPONENT LIBRARY (`frontend/src/components/ui.jsx`)

### 4.1 Core Components
| Component | Purpose | Accessibility |
|-----------|---------|---------------|
| `Panel` | Card container with title/subtitle | ✅ Semantic HTML |
| `Badge` | Status indicator with tone (red/amber/green/cyan/blue/violet) | ⚠️ Color-only meaning |
| `Table` | Sortable data table | ❌ No keyboard nav |
| `Kpi` | Key-value metric display | ✅ |
| `Feed` | Event stream list | ✅ |
| `PageHead` | Breadcrumb + title + actions | ✅ |
| `Code` | Monospace code block | ✅ |
| `Tabs` | Tab navigation | ⚠️ No ARIA |
| `Bar` | Progress bar | ✅ |
| `LiveBadge` | "LIVE" / "OFFLINE" indicator | ✅ |
| `RealtimeChip` | Connection status | ✅ |

### 4.2 Layout (`Layout.tsx` — 24.6K lines)
- **Sidebar navigation** with collapsible sections
- **Top bar:** User menu, notifications, realtime status, search
- **Responsive:** Mobile drawer, desktop sidebar
- **Auth integration:** User avatar, role badge, sign out

---

## 5. REAL-TIME ARCHITECTURE

### 5.1 Event Sources
| Source | Hook | Endpoint | Events |
|--------|------|----------|--------|
| SSE Global | `useRealtime` | `/api/v1/events/global` | All platform events |
| SSE Topic | `useRealtime` | `/api/v1/events/{topic}` | Filtered events |
| WebSocket | `useRealtime` | `/api/v1/ws/events` | Binary job progress |
| Polling | `usePollingApi` | Various | Fallback for non-realtime |

### 5.2 Event Handling
```tsx
// realtime.js — event normalization
const rt = useRealtime();
// rt.events[] — array of {type, ts, payload}
// rt.connected — boolean
// rt.connect()/disconnect()
// severityOf(type) — maps event type to severity
// isSystemEvent(type) — filters internal events
```

### 5.3 Integration Example (CommandCenter)
```tsx
const rt = useRealtime();
const liveFeed = rt.events.filter(e => !isSystemEvent(e.type)).slice(0, 6).map(e => ({
  t: new Date(e.ts).toLocaleTimeString(),
  tag: e.type.replace(/^(platform|monitor)\./, "").replace(/_/g, " ").slice(0, 22).toUpperCase(),
  text: String(e.payload?.detail || e.payload?.target || ""),
  severity: severityOf(e.type),
}));
```

---

## 6. ENTERPRISE UX ASSESSMENT

### 6.1 Strengths (✅ Enterprise-Grade)
1. **Honest unknowns** — "UNKNOWN — no live evidence" not zeros
2. **Evidence-linked** — Every finding traces to source file/line
3. **Deterministic labeling** — "AI RECOMMENDATION - NOT COMPLIANCE DETERMINATION"
4. **Real-time by default** — SSE/WebSocket with polling fallback
5. **Code-split routes** — Fast initial load, lazy pages
6. **Keyboard navigation** — Basic focus management
7. **Responsive layout** — Mobile drawer, desktop sidebar
8. **Error boundaries** — Per-route error recovery
9. **Loading states** — Suspense boundaries with skeletons

### 6.2 Weaknesses (❌ Gaps)
| Issue | Location | Impact |
|-------|----------|--------|
| **No keyboard navigation in Tables** | `Table` component | Accessibility fail |
| **Color-only status meaning** | `Badge` tones | Color-blind unusable |
| **Missing ARIA on Tabs** | `Tabs` component | Screen reader fail |
| **No column sorting/filtering UI** | `Table` | Large datasets unusable |
| **No virtualized lists** | `Feed`, `Table` | Performance at scale |
| **Hardcoded empty states** | Many pages | "No findings — clean result" may be misleading |
| **No export affordances** | Most pages | CSV/PDF export missing from UI |
| **Inconsistent date formatting** | Various | Some ISO, some locale |
| **No tour/onboarding** | First login | Complex UI unexplained |
| **No command palette** | Global | Power user efficiency |

### 6.3 Fake/Mock Data Detection
**Scanned for:** `mock`, `fake`, `demo`, `sample`, `placeholder`, hardcoded arrays
**Found:** 
- `CommandCenter.tsx` — `networkAssets = Array(invCounts.network_assets ?? 0).fill(null)` — creates array of nulls for display count only
- `DevSecOps.tsx` — Default Dockerfile, packages, feed in state — **editable by user, not fake data**
- `SbomScanTab` — Default feed text — **placeholder, not rendered as data**

**Verdict:** **No fake data in production views.** Defaults are placeholders for user input; all displayed data comes from live APIs.

---

## 7. SECURITY ISSUES

| Issue | Location | Severity |
|-------|----------|----------|
| **No CSP header** | `vite.config.js` / nginx | P2 |
| **Inline styles** | Many components (style={{...}}) | P3 — CSP violation |
| **`dangerouslySetInnerHTML`** | Not found | ✅ |
| **XSS via event payload** | `realtime.js` → `Feed` | P2 — payload rendered as text but not sanitized |
| **Auth token in localStorage** | `AuthProvider` | P2 — XSS exposure |
| **No rate limit UI feedback** | Forms | P3 — UX only |

---

## 8. TESTING COVERAGE

### 8.1 Test Files
| File | Purpose |
|------|---------|
| `App.test.tsx` | Route rendering, auth flow |
| `pages.smoke.test.tsx` | All 71 pages render without crash |
| `Tenancy.test.tsx` | Tenant switching |
| `ui.test.tsx` | Component rendering |
| `PortfolioDependencyPanel.test.tsx` | Graph panel |
| `setup.ts` | Offline fetch stub (rejects all calls) |

### 8.2 Test Philosophy
- **Offline-first:** `fetch` stubbed to reject — pages must render empty/offline state
- **Mock per test:** `mockFetch({ "/api/...": {...} })` for specific scenarios
- **No integration tests** against live backend
- **No E2E tests** (Playwright/Cypress not configured)

### 8.3 Coverage Gaps
- No visual regression tests
- No accessibility tests (axe-core not configured)
- No performance tests
- No API contract tests

---

## 9. BUILD & DEPLOYMENT

### 9.1 Vite Config (`vite.config.js`)
- React plugin
- Base: `/` (served from nginx)
- Build output: `dist/`
- Chunk splitting: Manual `manualChunks` for vendor/react-router/framer-motion

### 9.2 Docker (`.docker/frontend/Dockerfile`)
- Node 20 Alpine
- `npm ci` → `npm run build` → nginx static serve
- Non-root user, `cap_drop: ALL`

### 9.3 Nginx (`.docker/nginx/`)
- Serves frontend at `/`
- Proxies `/api` to API service
- TLS termination (prod)

---

## 10. FRONTEND-BACKEND CONTRACT

### 10.1 Type Definitions (`frontend/src/types.ts`)
- `ApiResult<T>` — discriminated union
- `LiveScanStatus`, `LiveAlertsResponse` — specific shapes
- **Gap:** No shared types package — frontend types drift from backend schemas

### 10.2 Version Tolerance
- Frontend checks `source === "live"` before using data
- Graceful degradation when backend fields missing
- **Risk:** Backend schema changes break frontend silently (no compile-time check)

---

## 11. ACCESSIBILITY AUDIT (WCAG 2.1 AA)

| Criterion | Status | Evidence |
|-----------|--------|----------|
| 1.1.1 Non-text Content | ⚠️ Partial | Icons have no alt text; Phosphor icons SVG |
| 1.3.1 Info and Relationships | ⚠️ Partial | Tables lack `<th scope="col">`; Tabs lack ARIA |
| 1.4.1 Use of Color | ❌ Fail | Badge tones convey meaning without text |
| 2.1.1 Keyboard | ❌ Fail | Table, Tabs, Feed not keyboard navigable |
| 2.4.3 Focus Order | ✅ Pass | Logical tab order |
| 2.4.7 Focus Visible | ⚠️ Partial | Custom focus styles inconsistent |
| 3.1.1 Language of Page | ✅ Pass | `lang="en"` on html |
| 3.2.1 On Focus | ✅ Pass | No unexpected changes |
| 4.1.2 Name, Role, Value | ⚠️ Partial | Custom components lack ARIA roles |

---

## 12. PERFORMANCE

### 12.1 Bundle Size (est.)
| Chunk | Size (gzipped) |
|-------|----------------|
| vendor | ~120 KB |
| react-router | ~40 KB |
| framer-motion | ~60 KB |
| Main (CommandCenter) | ~80 KB |
| Per-page chunks | 10-50 KB each |

### 12.2 Runtime Performance
- **Realtime events:** `rt.events` grows unbounded (slice(0,6) for display but array accumulates)
- **Polling:** 7 concurrent polls in CommandCenter (5s-20s intervals)
- **Large pages:** `DevSecOps.tsx` 93K lines — should be split
- **No memoization:** `useMemo`/`useCallback` rarely used

---

## 13. RECOMMENDATIONS

### P0 — Critical
1. **Fix accessibility** — Table keyboard nav, Badge text+color, Tabs ARIA
2. **Add CSP header** — nginx config + remove inline styles
3. **Bound realtime event array** — circular buffer or TTL cleanup

### P1 — High
4. **Virtualized tables/feeds** — react-window for 1000+ rows
5. **Column sorting/filtering** — Table component enhancement
6. **Shared types package** — `shared/types` published to npm/registry
7. **Export affordances** — CSV/PDF buttons on all data views

### P2 — Medium
8. **Command palette** — Cmd+K global search/actions
9. **Onboarding tour** — Driver.js or similar for first-time users
10. **Date formatting consistency** — Single `formatDate()` utility
11. **Split DevSecOps page** — 93K lines → multiple sub-pages

### P3 — Enhancement
12. **Visual regression tests** — Playwright + Percy/Chromatic
13. **Performance budgets** — CI gate on bundle size, LCP
14. **Dark mode** — CSS variables already support; add toggle
15. **Internationalization** — `i18n` folder exists but unused
---

## UPDATE — round 16 verification + build (2026-10-09)

**Built (the report's P0 accessibility items):**

- `Tabs` now implements the ARIA tabs pattern: `role="tablist"`/`role="tab"`,
  `aria-selected`, roving tabindex (only the active tab is tab-reachable),
  ArrowLeft/ArrowRight (wrapping) and Home/End navigation with focus
  following selection.
- `Table` clickable rows are real controls: `tabIndex=0`, `role="button"`,
  Enter/Space activation, `aria-selected` on the selected row, and every
  header carries `scope="col"`.
- Both covered by tests (`ui.test.tsx`, suite 130 → 132) and the pages smoke
  suite still passes with the stricter markup.

**Verified stale:**

- "Hbom.tsx is a stub / no data source" — stale: the page polls
  `GET /api/v1/live-scan/bom` and renders `hbom.components` (TPM/HSM/CPU
  crypto/secure elements) with an honest empty state.
- "rt.events grows unbounded" — stale: the realtime store caps the event
  buffer (EVENT_CAP) and the audit's own §12.2 concern was fixed earlier.
- "Badge color-only meaning" — partially stale: Badge always renders its
  text children next to the tone dot; tone is reinforcement, not the only
  channel.

**Remains open (accepted, not built this round):** CSP headers (needs the
inline-style audit first — a strict CSP would break the current UI),
virtualized tables, command palette, shared types package, i18n. These are
UX/enhancement work, not correctness gaps.
