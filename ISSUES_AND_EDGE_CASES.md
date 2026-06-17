# Download Trap Guard — Issues & Edge Cases

Audit of **v2.1.0** (`src/content.ts`, `src/analysis.ts`, `manifest.json`, `background.ts`, `README.md`).

**Severity legend:** Critical · High · Medium · Low · Info · Accepted limitation

---

## Status overview

| Status | Meaning |
|--------|---------|
| **Fixed** | Addressed in code or docs |
| **Accepted** | Known limitation by design or browser constraints |
| **Open** | Not yet addressed (should be none for actionable items) |

---

## Bugs & functional issues

| ID | Severity | Issue | Status | Notes |
|----|----------|-------|--------|-------|
| B-01 | **Critical** | Dismiss removed click protection | **Fixed** | Dismiss hides banner only; highlights + `WeakSet` link tracking keep interception active. |
| B-02 | **High** | README implied general-site scanning | **Fixed** | README + popup + manifest aligned to Zoho-only. |
| B-03 | **Medium** | `EXECUTABLE_EXTENSIONS` only used in Zoho context | **Accepted** | Intentional product scope; constants live in `analysis.ts` and apply inside ticket content. |
| B-04 | **Medium** | Background message handler unused | **Fixed** | `content.ts` sends `DOWNLOAD_TRAP_DETECTED`; service worker logs + badge. |
| B-05 | **Medium** | Polling stopped after ~60s | **Fixed** | Continuous 5s interval rescan. |
| B-06 | **Low** | `lastWarnedKey` seemed unused | **Fixed** | Suppresses re-rendering banner when risk set unchanged; still re-applies highlights. |
| B-07 | **Low** | Only first `<img>` per anchor scanned | **Fixed** | All images inside each anchor are scanned. |

---

## Documentation & consistency

| ID | Severity | Issue | Status | Notes |
|----|----------|-------|--------|-------|
| D-01 | **High** | README vs popup vs manifest mismatch | **Fixed** | All describe Zoho Desk ticket scanning. |
| D-02 | **Medium** | Hard-coded Windows install path | **Fixed** | Generic `dist/` path. |
| D-03 | **Low** | Desktop HTML test in README | **Fixed** | Zoho ticket test steps. |
| D-04 | **Info** | `SKIP_SCAN_HOSTS` / `shouldSkipPage` dead code | **Fixed** | Removed; manifest limits injection to ticket URLs. |

---

## Architecture & dead code

| ID | Severity | Issue | Status | Notes |
|----|----------|-------|--------|-------|
| A-01 | **Medium** | Content script on all URLs | **Fixed** | `matches` limited to `/tickets/details/` routes. |
| A-02 | **Low** | Duplicate banner styles | **Fixed** | Single source: `warning.css`. |
| A-03 | **Low** | No extension icons | **Fixed** | Generated `icons/icon{16,48,128}.png` at build. |
| A-04 | **Info** | Empty `permissions` | **Fixed** | `storage` permission documented in README + `PRIVACY.md`. |

---

## Performance

| ID | Severity | Issue | Status | Notes |
|----|----------|-------|--------|-------|
| P-01 | **Medium** | Full DOM walk every scan | **Fixed** | Scans anchors only inside ticket-content containers. |
| P-02 | **Medium** | O(n²) dedupe in `queryAllDeep` | **Fixed** | `Set`-based dedupe. |
| P-03 | **Low** | `clearWarnings` walked full DOM | **Fixed** | Tracks `activeHighlights` refs only. |
| P-04 | **Low** | Multiple instances per iframe | **Accepted** | Required for ticket bodies in iframes; `watching` guard prevents duplicate setup per frame. |
| P-05 | **Info** | 300 ms debounce | **Accepted** | Reasonable trade-off for SPA ticket UI. |

---

## Security & permission model

| ID | Severity | Issue | Status | Notes |
|----|----------|-------|--------|-------|
| S-01 | **Medium** | `<all_urls>` host permission | **Fixed** | Narrowed to ticket-detail URL patterns only. |
| S-02 | **Medium** | Soft block via `confirm()` | **Accepted** | Warning tool, not endpoint protection; agents can override after confirmation. |
| S-03 | **Low** | No reporting hook | **Fixed** | Service worker logs detections + session log + toolbar badge. |
| S-04 | **Info** | `escapeHtml` attribute safety | **Fixed** | Escapes `& < > " '` for text nodes. |

---

## Detection gaps (false negatives)

| ID | Scenario | Status | Notes |
|----|----------|--------|-------|
| N-01 | Not in Zoho Desk context | **Accepted** | Product scope: Zoho ticket pages only. |
| N-02 | Link outside ticket content containers | **Fixed** | Added `ticketDesc`, `mailContent` selectors; expanded root scan. |
| N-03 | No `<a><img></a>` pattern | **Accepted** | Buttons/divs/onclick traps require different heuristics. |
| N-04 | Image not nested in anchor | **Accepted** | Overlay traps need layout analysis. |
| N-05 | SVG / background-image traps | **Accepted** | No `<img>` element to analyze. |
| N-06 | Download via `Content-Disposition` | **Accepted** | No network response inspection in content script. |
| N-07 | Extension only in query/hash | **Fixed** | `extensionFromUrlParts()` checks query string and hash. |
| N-08 | Redirect chains | **Accepted** | Only `href` analyzed, not final redirect target. |
| N-09 | `blob:` / `filesystem:` links | **Accepted** | Uncommon in tickets; skipped unless extension matches. |
| N-10 | Odd URL schemes (`ftp:`, etc.) | **Accepted** | Not in trap lists. |
| N-11 | Homograph / IDN `share.google` variants | **Fixed** | `isShareGoogleVariant()` + punycode hostname check. |
| N-12 | Typosquat hosts not in lists | **Accepted** | Cannot enumerate all variants; path extension check still applies. |
| N-13 | Non-Imgur image CDN lures | **Fixed** | `IMAGE_LURE_HOSTS` (imgur, ibb.co, postimg.cc, …). |
| N-14 | Right-click / copy / drag | **Fixed** | `contextmenu` blocked on flagged links with alert. |
| N-15 | Keyboard activation | **Fixed** | `keydown` intercepts Enter/Space on flagged links. |
| N-16 | Middle-click | **Accepted** | `auxclick` handled; browser may still open tab after confirm. |
| N-17 | `download` on trusted host | **Accepted** | Trust model assumes portal/CDN links are safe. |
| N-18 | MutationObserver attribute blind spot | **Fixed** | Observer watches `href` and `src` attribute changes. |
| N-19 | Closed shadow DOM | **Accepted** | Browser does not expose closed shadow roots. |
| N-20 | Ticket list / preview pane | **Accepted** | Extension only injects on `/tickets/details/` URLs. |

---

## False positives

| ID | Scenario | Status | Notes |
|----|----------|--------|-------|
| F-01 | Legitimate `.zip` image link | **Accepted** | Intentional strict match; agent confirms to proceed. |
| F-02 | Imgur image → Imgur album | **Fixed** | Imgur-to-Imgur links no longer flagged unless download extension present. |
| F-03 | `googledrive` substring match | **Fixed** | Removed bare `googledrive` from host-contains list. |
| F-04 | `.tar.gz` flagged as `.gz` | **Fixed** | `extensionFromPath` handles `.tar.gz` / `.tar.bz2`. |
| F-05 | `.js` links flagged | **Accepted** | `.js` treated as executable; rare in tickets. |
| F-06 | `.dmg` / `.pkg` on Mac tickets | **Accepted** | Strict archive list by design. |
| F-07 | `.docm` macro Office files | **Accepted** | Macro-enabled formats treated as risky. |
| F-08 | Zoho host outside ticket | **Accepted** | `isInsideTicketContent` limits findings to message bodies. |

---

## Zoho Desk–specific edge cases

| ID | Severity | Scenario | Status | Notes |
|----|----------|----------|--------|-------|
| Z-01 | **High** | Custom portal (`support.stayzltd.com`) | **Fixed (v2.3.0)** | Multi-frame bug: empty iframes were clearing the top banner; risks in email iframes now relay to top via background. Full-body scan, fast `share.google` path, iframe descent. |
| Z-02 | **High** | `stayzltd.com` globally trusted | **Fixed** | Removed from `TRUSTED_LINK_HOSTS`; same-portal trust via `isPortalInternalHost` only. |
| Z-03 | **Medium** | `isPortalInternalHost` last-two-labels | **Fixed** | Trusts only exact host + subdomains of current page host. |
| Z-04 | **Medium** | Class name coupling | **Accepted** | Inherent to DOM-based detection; expanded selector list mitigates. |
| Z-05 | **Medium** | Ticket in cross-origin iframe | **Fixed** | `shouldStartWatching()` starts on DOM markers without parent URL. |
| Z-06 | **Low** | Alternate agent URL shapes | **Accepted** | `path.includes("/tickets/details/")` covers most variants. |
| Z-07 | **Low** | `ZOHO_HOST_PATTERNS` uses `includes` | **Accepted** | Works for real Zoho hostnames. |
| Z-08 | **Info** | Comments / internal notes | **Fixed** | `CommentContent` + expanded roots included. |

---

## UI, click blocking & UX edge cases

| ID | Severity | Scenario | Status | Notes |
|----|----------|----------|--------|-------|
| U-01 | **Critical** | Dismiss removed protection | **Fixed** | See B-01. |
| U-02 | **Medium** | Banner showed max 3 risks | **Fixed** | Shows up to 10 items + “and N more” count. |
| U-03 | **Medium** | `confirm()` fatigue | **Accepted** | UX trade-off for a lightweight warning extension. |
| U-04 | **Low** | Banner prepended to `documentElement` | **Fixed** | Prepends to `body` when available. |
| U-05 | **Low** | Dismiss not persisted | **Fixed** | `chrome.storage.session` remembers dismiss per risk set. |
| U-06 | **Low** | Inconsistent highlight badge CSS | **Fixed** | Single `warning.css` source. |
| U-07 | **Info** | Emoji rendering | **Fixed** | Banner uses `!` icon class instead of emoji. |

---

## Cross-frame & cross-origin edge cases

| ID | Scenario | Status | Notes |
|----|----------|--------|-------|
| X-01 | Cross-origin iframe ticket body | **Fixed** | DOM-based `shouldStartWatching()` fallback. |
| X-02 | Cross-origin top window banner | **Accepted** | Banner falls back to iframe `document` when top is inaccessible. |
| X-03 | Multiple risky iframes | **Accepted** | Each frame scans independently; rare in practice. |
| X-04 | `lastWarnedKey` per frame | **Accepted** | Per-frame state; highlights still apply locally. |
| X-05 | Split banner / highlights | **Accepted** | Same-origin top gets banner; highlights stay in source frame. |

---

## DOM & markup edge cases

| ID | Scenario | Status | Notes |
|----|----------|--------|-------|
| M-01 | Tracking pixel filter | **Accepted** | Skips images &lt; 16px when dimensions known. |
| M-02 | Lazy-loaded zero-size images | **Accepted** | Not filtered until dimensions load; rescans catch them. |
| M-03 | Relative `href` resolution | **Fixed** | `getLinkUrl` + `URL` with `baseUrl`. |
| M-04 | `javascript:` / `data:` / `mailto:` | **Fixed** | Explicitly excluded in `analyzeImageLink`. |
| M-05 | Nested interactive elements | **Accepted** | Browser-dependent; `closest("a")` used. |
| M-06 | `pointer-events: none` on image | **Fixed** | Click hits parent anchor; flagged link intercepted. |
| M-07 | Dynamically removed trap | **Fixed** | Observer + interval clear UI when risks gone. |

---

## URL parsing edge cases

| ID | Scenario | Status | Notes |
|----|----------|--------|-------|
| R-01 | `archive.tar.gz` → `.gz` | **Fixed** | `.tar.gz` / `.tar.bz2` handled explicitly. |
| R-02 | `isImagePreviewUrl` bmp/ico | **Fixed** | Regex includes bmp/ico. |
| R-03 | `share.google` host match | **Fixed** | Exact + variant detection. |
| R-04 | URL with credentials | **Accepted** | `URL` API parses correctly. |
| R-05 | IPv6 / localhost | **Accepted** | Parsed when valid. |
| R-06 | `SKIP_SCAN_HOSTS` on non-Zoho | **Fixed** | Removed; manifest scopes injection. |

---

## Build, manifest & distribution

| ID | Severity | Issue | Status | Notes |
|----|----------|-------|--------|-------|
| M-01 | **Info** | Build output | **Fixed** | `npm run build` → `dist/`. |
| M-02 | **Info** | No automated tests | **Fixed** | `npm test` runs `tests/analysis.test.mjs`. |
| M-03 | **Info** | No CI / lint | **Accepted** | TypeScript strict compile + test script; CI optional. |
| M-04 | **Low** | Store readiness | **Fixed** | Icons, `PRIVACY.md`, narrowed permissions, permission docs. |

---

## Recommended test matrix

### Should detect (inside Zoho ticket content)

- [ ] `<a href="https://share.google/..."><img src="..."></a>`
- [ ] Image link to `https://evil.com/payload.zip`
- [ ] Imgur / ibb.co image linking to non-image external URL
- [ ] Path ending in `.exe`, `.msi`, `.docm`, `.7z`
- [ ] `?file=payload.zip` in query string

### Should not detect

- [ ] Traps outside `/tickets/details/` URLs (extension not injected)
- [ ] Plain text link to `.zip` (no image in anchor)
- [ ] 1×1 tracking pixel in ticket (&lt; 16px)
- [ ] Trusted Zoho CDN image links
- [ ] Imgur image → Imgur gallery (same host)

### UX / blocking

- [ ] Click flagged image → `confirm()` appears
- [ ] Cancel → navigation blocked
- [x] Dismiss banner → click image → still warns
- [x] Dismiss banner → stays hidden until new risks or new session
- [ ] Right-click on flagged image → blocked with alert
- [ ] Enter on focused flagged link → `confirm()` appears
- [ ] Trap `href` changed via attribute → rescan triggers

### Zoho layouts

- [ ] `support.stayzltd.com` ticket details URL
- [ ] Ticket in iframe (portal embedding)
- [ ] Lazy-loaded reply after 60+ seconds

---

## Summary

| Category | Fixed | Accepted | Total |
|----------|-------|----------|-------|
| Bugs | 6 | 1 | 7 |
| Documentation | 4 | 0 | 4 |
| Architecture | 4 | 0 | 4 |
| Performance | 3 | 2 | 5 |
| Security | 3 | 1 | 4 |
| False negatives | 8 | 12 | 20 |
| False positives | 3 | 5 | 8 |
| Zoho-specific | 5 | 3 | 8 |
| UI / UX | 6 | 1 | 7 |
| Cross-frame | 1 | 4 | 5 |
| DOM | 4 | 3 | 7 |
| URL parsing | 4 | 2 | 6 |
| Build / distribution | 3 | 1 | 4 |

**v2.1.0** resolves all actionable code and documentation issues. Remaining rows are **accepted limitations** inherent to a lightweight, Zoho-scoped, client-side warning extension.

---

## v2.6.1 — URL-as-label hijack phishing pattern

**Real-world example detected:**

- **Ticket**: "Special Needs Room Booking" (#111767)
- **Sender**: `cusidomitaq08@gmail.com` (free Gmail, not Booking.com)
- **Technique**: Anchor text shows `https://booking.com/complaint?op_token=…` but actual `href` goes to `https://publikt-gstx.com` — a typosquat/throwaway domain
- **Extra deception**: Booking.com logo image in email header reinforces the illusion

### Changes to detection (v2.6.1)

| Signal | Before | After |
|--------|--------|-------|
| Href/text mismatch (plain text label) | score 75 | score 75 |
| **Href/text mismatch (label IS a full URL)** | score 75 | **score 88** |
| Free-webmail + brand impersonation combined | score 18 | **score 22** |
| `complaint` in urgency keyword list | not present | **added** |
| `compensation`, `dispute`, `chargeback` etc. | not present | **added** |

Raising the mismatch score when the label itself contains `https://` — the attacker deliberately wrote a fake trusted URL as visible link text, which is a high-confidence deception signal.

*Last updated after v2.6.1.*
