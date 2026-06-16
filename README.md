# Download Trap Guard

Simple browser extension — warns when a website or **Zoho Desk email** contains a **clickable image** that would **download a file**.

No backend. No Docker. No database.

---

## Install (one time)

1. Install **Node.js** from https://nodejs.org (LTS is fine)

2. Open PowerShell in this folder (`E:\typescript`):

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
   ```
   E:\typescript\dist
   ```

Done. The extension is active.

---

## What it does

- **Ignores** Google Images, Bing, YouTube, social media, and other normal image sites
- **Zoho Desk tickets** — scans ticket messages on portals like `support.stayzltd.com` (path `/agent/.../tickets/details/`)
- **Catches `share.google/...` links** on ticket images (zip download phishing — no `.zip` in the URL)
- **Strict matching** on normal websites — executables only, not random URL substrings
- Shows a **red banner** on ticket phishing images with the suspicious link shown
- Blocks click unless you confirm

---

## After you change code

```powershell
npm run build
```

Then go to `chrome://extensions` and click the **refresh** icon on the extension.

---

## Test it

Create a simple HTML file on your desktop:

```html
<a href="https://example.com/malware.exe">
  <img src="https://via.placeholder.com/200" alt="click me">
</a>
```

Open that file in the browser — you should see the warning banner.

---

## Uninstall

Remove the extension from `chrome://extensions` — nothing else to clean up.
