# Download Trap Guard

Simple browser extension — warns when a **Zoho Desk ticket** contains a **clickable image** that would **download a file**.

No backend. No Docker. No database.

---

## Install (one time)

1. Install **Node.js** from https://nodejs.org (LTS is fine)

2. Open a terminal in this project folder:

```powershell
npm install
npm run build
```

3. Open Chrome or Edge:
   - Chrome: go to `chrome://extensions`
   - Edge: go to `edge://extensions`

4. Turn on **Developer mode**

5. Click **Load unpacked**

6. Select the **`dist`** folder inside this project:
   `dist/`

Done. The extension is active.

---

## What it does

- **Zoho Desk tickets only** — scans ticket messages on portals like `support.stayzltd.com` (path `/agent/.../tickets/details/`)
- **Unified risk scoring (v2.4)** — combines multiple signals (trap URL, large clickable image, link-text mismatch, sender/subject context) into one confidence score
- **Catches `share.google/...` links** on ticket images and **button-style links** (e.g. phishing “Send reply” buttons)
- **Large image traps** — flags big clickable images that link to untrusted external hosts (not only Imgur/CDN lures)
- **Link text mismatch** — warns when visible text says one site (e.g. `booking.com`) but the href goes elsewhere
- **Ticket context** — boosts risk for free-webmail senders, urgent subjects, and brand-impersonation language
- Shows a **red banner** on suspicious links/buttons with the destination URL shown
- Blocks click unless you confirm

---

## After you change code

```powershell
npm run build
```

Then go to `chrome://extensions` and click the **refresh** icon on the extension.

---

## Test it

Open a **Zoho Desk ticket details** page containing a clickable image that links to:

- a known trap host like `share.google/...`, or
- a URL that ends with an archive/executable extension like `.zip`, `.exe`, `.7z`, etc.

On detection you should see:

- a red banner at the top of the ticket,
- the suspicious image highlighted,
- and a `confirm()` warning when you click the image.

---

## Permissions

- Runs only on Zoho Desk **ticket detail** URLs (`/tickets/details/`).
- Uses `storage` (session only) to remember dismissed banners for the current browser session.
- See [PRIVACY.md](PRIVACY.md) for Chrome Web Store data usage and privacy disclosures.

---

## Uninstall

Remove the extension from `chrome://extensions` — nothing else to clean up.
