# Chrome Web Store listing — Download Trap Guard

Copy from this file when submitting **v1.0.0**. Host `PRIVACY.md` at a public URL and paste that link in the store form.

---

## Single purpose

Download Trap Guard warns Zoho Desk support agents when a ticket contains clickable images, links, or buttons that may trigger a malicious file download (for example `.zip` traps or `share.google` lures). It shows an on-page warning and asks for confirmation before the user clicks.

---

## Permission justification

### `storage`

Session-only local data: dismissed warning banners, a rolling log of up to 50 detections (page URL, count, timestamp) for the extension badge, and per-tab risk results to show the banner. Not transmitted off-device.

### `scripting`

Re-injects the content script on Zoho Desk ticket detail pages after the page loads so ticket email content in iframes can be scanned. Only runs when the tab URL contains `/tickets/details/`.

### Host permissions

| Pattern | Justification |
|---------|---------------|
| `*://*.stayzltd.com/*` | Custom Zoho Desk portal |
| `*://*.zoho.com/*`, `*://*.zoho.eu/*`, `*://*.zohodesk.com/*` | Zoho Desk agent interface |
| `*://*.zohopublic.com/*`, `*://*.zappsusercontent.com/*`, `*://*.zohostratus.com/*`, `*://*.zohocloud.ca/*` | Zoho CDN and embedded frames for ticket/email views |

---

## Data usage (checkboxes)

| Category | Check? | Notes |
|----------|--------|-------|
| Website content | **Yes** | Links, images, button text on ticket pages — scanned locally; not uploaded |
| User activity | **Yes** | Session-only detection log and dismiss state — not keystroke/scroll logging |
| Personal communications | **Yes** | Ticket email threads read locally for scan; bodies not stored or transmitted |
| Personally identifiable information | **No** | Not extracted or transmitted |
| Health information | **No** | |
| Financial and payment information | **No** | |
| Authentication information | **No** | |
| Location | **No** | |
| Web history | **No** | Only active ticket detail tabs, not browsing history |

**Certification:** All processing is on-device. No data is sold or used for unrelated purposes. Disclosures match [PRIVACY.md](PRIVACY.md).

---

## Privacy policy URL

Publish `PRIVACY.md` at a public HTTPS URL, for example:

- `https://www.stayzltd.com/policies/download-trap-guard-privacy`
- or GitHub Pages / similar

Paste that URL into the Chrome Web Store **Privacy policy** field.
