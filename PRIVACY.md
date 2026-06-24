# Privacy Policy — Download Trap Guard

**Last updated:** June 2026

## Summary

Download Trap Guard is a browser extension with a **single purpose**: warn Zoho Desk support agents when a ticket contains clickable content (images, links, or buttons) that may trigger a malicious file download.

The extension runs **entirely in your browser**. It does **not** send ticket content, URLs, or personal data to any server operated by the extension developer. It does **not** sell user data or use it for advertising.

---

## Single purpose

Download Trap Guard scans **Zoho Desk ticket detail pages** only and shows an on-page warning when suspicious download traps are detected. It may block a click until you confirm. It is not a general ad blocker, spam filter, or ticket management tool.

---

## What user data is handled

This disclosure matches the Chrome Web Store **Data usage** form for Download Trap Guard.

### Website content — handled locally

The extension reads **ticket page content** in your browser to perform its security scan, including:

- Hyperlinks and destination URLs
- Images and whether they are wrapped in clickable links
- Visible link or button text

This content is processed **in memory** to evaluate risk. Full page HTML is **not** uploaded anywhere.

### Personal communications — handled locally

Support tickets often contain **email threads** and customer messages. The extension reads that content **only on the ticket page you have open**, in order to detect malicious links and download traps.

The extension does **not** archive, export, or transmit email bodies or chat messages.

### User activity — stored locally (session only)

When a trap is detected, the extension may store **limited activity metadata** in **session storage** (cleared when the browser session ends):

- The ticket page URL where a detection occurred
- Detection count and timestamp (rolling log of up to 50 entries, for the extension badge)
- Per-tab detection details (target URL, reason, confidence) to show the warning banner
- Whether you dismissed the warning banner for a given page

This is **not** keystroke logging, scroll tracking, mouse monitoring, or general browsing history.

---

## What is not collected

Download Trap Guard does **not** collect or transmit:

| Category | Collected? |
|----------|------------|
| Personally identifiable information (name, address, email, age, ID) | No — not extracted or stored as a separate dataset |
| Health information | No |
| Financial or payment information | No |
| Authentication information (passwords, PINs, credentials) | No |
| Location (GPS, IP geolocation) | No |
| Web history (list of all sites you visit) | No — the extension only runs on Zoho Desk ticket URLs you open |

Also:

- No analytics or third-party telemetry
- No sale or sharing of user data with advertisers or data brokers
- No backend that receives ticket content

**Note:** Ticket pages may *display* customer names or email addresses inside legitimate support emails. The extension does not purposefully collect that information; it may pass over such text in memory while scanning links and images only.

---

## What is stored on your device

All storage uses **`chrome.storage.session`** (session-only; cleared when the browser closes):

| Data | Purpose |
|------|---------|
| Dismissed-banner state | Avoid re-showing a banner you already dismissed on the same page |
| Detection log (last 50) | Extension badge and service worker diagnostics |
| Per-tab risk results | Display the warning banner across frames on the same ticket tab |

Nothing in this storage is synced to the cloud by the extension.

---

## Permissions

| Permission | Why it is needed |
|------------|------------------|
| `storage` | Session-only data described above (dismiss state, detection log, per-tab risks). |
| `scripting` | Re-inject the scanner on Zoho Desk ticket detail pages after content loads (including email iframes). Runs only when the tab URL contains `/tickets/details/`. |
| Host access on Zoho and Stayz domains | Inject the content script on Zoho Desk portals and embedded Zoho frames where ticket messages appear. |

**Host patterns in the manifest:**

- `*.stayzltd.com` — custom Zoho Desk portal
- `*.zoho.com`, `*.zoho.eu`, `*.zohodesk.com` — Zoho Desk agent interface
- `*.zohopublic.com`, `*.zappsusercontent.com`, `*.zohostratus.com`, `*.zohocloud.ca` — Zoho-hosted assets and embedded content used by Desk

Scanning logic is limited to **ticket detail pages** (`/tickets/details/`). Broader host access is required because Zoho loads ticket email HTML across subdomains and iframes.

---

## Data retention and deletion

- Session storage is cleared when you close the browser (or end the browsing session, depending on browser behavior).
- Uninstalling the extension removes all extension data from your browser.

---

## Changes to this policy

If this policy changes, the “Last updated” date above will be revised. Material changes will be reflected in the Chrome Web Store listing before the next published version.

---

## Contact

For questions about this extension or this privacy policy, contact your organization’s IT administrator or the extension maintainer at **Stayz Ltd**.
