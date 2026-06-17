# Privacy Policy — Download Trap Guard

**Last updated:** June 2026

## Summary

Download Trap Guard runs entirely in your browser. It does **not** send ticket content, URLs, or personal data to any external server.

## What the extension accesses

- **Zoho Desk ticket detail pages** only (URLs containing `/tickets/details/`).
- **DOM content** on those pages to find clickable images whose links may trigger file downloads.

## What is stored locally

- **Session storage** (cleared when the browser closes):
  - Whether you dismissed the warning banner for the current set of traps on a page.
  - A short rolling log (last 50 detections) for the extension badge / service worker — not transmitted off-device.

## What is not collected

- No analytics or telemetry services.
- No account credentials.
- No email bodies uploaded to a backend.

## Permissions

| Permission | Why |
|------------|-----|
| `storage` | Remember dismissed banners and detection log for the current browser session. |
| Host access on `/tickets/details/*` | Inject the scanner only on Zoho Desk ticket pages. |

## Contact

For questions about this extension, contact your organization's IT administrator or the extension maintainer.
