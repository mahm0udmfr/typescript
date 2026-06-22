import assert from "node:assert/strict";
import {
  analyzeImageLink,
  analyzeNavigationTarget,
  extensionFromPath,
  extensionFromUrlParts,
  isShareGoogleVariant,
  isSuspiciousCtaLabel,
  extractUrlsFromOnclick,
  checkDownloadTrapHost,
  extractDomainFromText,
  checkHrefTextMismatch,
  finalizeRiskScore,
  isFreeWebmailHost
} from "../dist/analysis.esm.js";

assert.equal(extensionFromPath("/files/archive.tar.gz"), ".tar.gz");
assert.notEqual(extensionFromPath("/files/archive.tar.gz"), ".gz");

assert.equal(extensionFromUrlParts("/download", "?file=payload.zip", ""), ".zip");
assert.equal(extensionFromUrlParts("/view", "", "#setup.exe"), ".exe");

assert.equal(isShareGoogleVariant("share.google"), true);
assert.equal(checkDownloadTrapHost("share.google").dangerous, true);
assert.equal(isSuspiciousCtaLabel("Send reply"), true);
assert.equal(isSuspiciousCtaLabel("Kind regards"), false);
assert.equal(isFreeWebmailHost("carlotta@libero.it"), true);

assert.equal(extractDomainFromText("Visit www.booking.com/reservation"), "booking.com");
assert.equal(extractDomainFromText("Booking.com Customer Service"), null);

const mismatch = checkHrefTextMismatch(
  "www.booking.com/reservation",
  "share.google",
  "support.stayzltd.com"
);
assert.ok(mismatch);
assert.ok(mismatch.score >= 70);

assert.equal(
  checkHrefTextMismatch("Booking.com Customer Service", "support.stayzltd.com", "support.stayzltd.com"),
  null
);

assert.deepEqual(
  extractUrlsFromOnclick("window.location.href='https://share.google/abc'"),
  ["https://share.google/abc"]
);

// Tier A: share.google on button-styled anchor
const buttonTrap = analyzeNavigationTarget(
  "https://share.google/VLjnaE5UtUS26hV43",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/1",
  { kind: "button-link", label: "Send reply", buttonStyled: true }
);
assert.equal(buttonTrap.dangerous, true);
assert.ok(buttonTrap.confidence >= 98);

// Tier A: plain text link to share.google
const textTrap = analyzeNavigationTarget(
  "https://share.google/abc",
  "support.example.com",
  "https://support.example.com/tickets/details/1",
  { kind: "text-link", label: "click here" }
);
assert.equal(textTrap.dangerous, true);

// Trusted booking link should stay safe
const plainLink = analyzeNavigationTarget(
  "https://www.booking.com/hotel/gb/example",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  { kind: "text-link", label: "View reservation" }
);
assert.equal(plainLink.dangerous, false);

// Phase A: suspicious CTA + unknown host (unified score)
const ctaTrap = analyzeNavigationTarget(
  "https://evil-unknown.example/invoice",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  { kind: "button-link", label: "View invoice", buttonStyled: true }
);
assert.equal(ctaTrap.dangerous, true);

// Phase A: href/text mismatch
const mismatchTrap = analyzeNavigationTarget(
  "https://evil-phish.example/download",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  { kind: "text-link", label: "https://www.booking.com/reservation" }
);
assert.equal(mismatchTrap.dangerous, true);
assert.ok(mismatchTrap.reason.includes("booking.com"));

// Phase A: large image + external untrusted host
const largeImageTrap = analyzeNavigationTarget(
  "https://evil-phish.example/page",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  { kind: "image-link", imgSrc: "https://cdn.example/screenshot.png", imgWidth: 420, imgHeight: 280 }
);
assert.equal(largeImageTrap.dangerous, true);

// Phase A: ticket context boosts borderline image trap
const contextTrap = analyzeNavigationTarget(
  "https://unknown-host.example/verify",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  {
    kind: "image-link",
    imgSrc: "https://cdn.example/ui.png",
    imgWidth: 200,
    imgHeight: 150,
    ticket: {
      senderEmail: "carlotta@libero.it",
      subject: "Urgent payment verification for your hotel booking",
      senderDisplayName: "Hotel Reservations"
    }
  }
);
assert.equal(contextTrap.dangerous, true);
assert.ok(contextTrap.confidence >= 70);

// Unified score combiner
const combined = finalizeRiskScore([
  { score: 40, reason: "signal a" },
  { score: 35, reason: "signal b" }
]);
assert.equal(combined.dangerous, true);
assert.equal(combined.confidence, 75);

const trap = analyzeImageLink(
  "https://share.google/abc",
  "https://i.imgur.com/x.png",
  "support.example.com",
  "https://support.example.com/tickets/details/1"
);
assert.equal(trap.dangerous, true);

const zipLink = analyzeImageLink(
  "https://evil.example/payload.zip",
  "https://cdn.example/img.png",
  "support.example.com",
  "https://support.example.com/tickets/details/1"
);
assert.equal(zipLink.dangerous, true);

const safe = analyzeImageLink(
  "https://desk.zoho.com/portal/image.png",
  "https://desk.zoho.com/portal/thumb.png",
  "desk.zoho.com",
  "https://desk.zoho.com/tickets/details/1"
);
assert.equal(safe.dangerous, false);

// Styled button without CTA should not alone reach threshold
const weakButton = analyzeNavigationTarget(
  "https://evil-unknown.example/page",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  { kind: "button-link", label: "More info", buttonStyled: true }
);
assert.equal(weakButton.dangerous, false);

const onclickTrap = analyzeNavigationTarget(
  "https://share.google/onclick-trap",
  "support.stayzltd.com",
  "https://support.stayzltd.com/tickets/details/1",
  { kind: "button-element", label: "Continue", buttonStyled: true }
);
assert.equal(onclickTrap.dangerous, true);

// ── Real-world case: "Special Needs Room Booking" phishing email ────────────
// Sender: cusidomitaq08@gmail.com pretending to be Booking.com
// Link TEXT: https://booking.com/complaint?op_token=eeceba7d-...
// Actual HREF: https://publikt-gstx.com (shown in browser status bar)
// → URL-as-label hijack: label shows a trusted URL but href goes elsewhere

const urlHijackTrap = analyzeNavigationTarget(
  "https://publikt-gstx.com/eeceba7d-e04f-4857-bb09-3d3e86893748",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/111767",
  {
    kind: "text-link",
    label: "https://booking.com/complaint?op_token=eeceba7d-e04f-4857-bb09-3d3e86893748",
    ticket: {
      senderEmail: "cusidomitaq08@gmail.com",
      subject: "Special Needs Room Booking complaint",
      senderDisplayName: "Adriene R"
    }
  }
);
assert.equal(urlHijackTrap.dangerous, true, "URL hijack trap should be flagged");
assert.ok(urlHijackTrap.confidence >= 88, `URL hijack confidence too low: ${urlHijackTrap.confidence}`);
assert.ok(urlHijackTrap.reason.includes("booking.com"), `Reason should mention booking.com: ${urlHijackTrap.reason}`);

// Sender + brand impersonation + CTA button → combined should reach threshold
const brandImpersonation = analyzeNavigationTarget(
  "https://publikt-gstx.com/token",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/111767",
  {
    kind: "button-link",
    label: "Review and respond",
    buttonStyled: true,
    ticket: {
      senderEmail: "attacker@gmail.com",
      subject: "Booking.com complaint about your property",
      senderDisplayName: "Booking.com Support"
    }
  }
);
assert.equal(brandImpersonation.dangerous, true, "Brand impersonation + CTA button should be flagged");

// ── Booking.com header IMAGE is the phishing trap ───────────────────────────
// Attacker wraps the Booking.com logo <img> in <a href="https://publick-gstx.com/">.
// Even when image dimensions are 0 (not yet loaded), free webmail sender +
// brand impersonation context pushes the score over the threshold.

const imageTrapNoSize = analyzeNavigationTarget(
  "https://publick-gstx.com/",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/111767",
  {
    kind: "image-link",
    imgSrc: "https://q.bstatic.com/static/img/booking/booking_logo_white.png",
    imgWidth: 0,
    imgHeight: 0,
    ticket: {
      senderEmail: "cusidomitaq08@gmail.com",
      subject: "Special Needs Room Booking complaint",
      senderDisplayName: "Adriene R"
    }
  }
);
assert.equal(imageTrapNoSize.dangerous, true, "Image trap should flag even with 0 dimensions when sender is free webmail + brand impersonation");
assert.ok(imageTrapNoSize.confidence >= 70, `imageTrapNoSize confidence: ${imageTrapNoSize.confidence}`);

const imageTrapLarge = analyzeNavigationTarget(
  "https://publick-gstx.com/",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/111767",
  {
    kind: "image-link",
    imgSrc: "https://q.bstatic.com/static/img/booking/booking_logo_white.png",
    imgWidth: 600,
    imgHeight: 120,
    ticket: {
      senderEmail: "cusidomitaq08@gmail.com",
      subject: "Special Needs Room Booking complaint",
      senderDisplayName: "Adriene R"
    }
  }
);
assert.equal(imageTrapLarge.dangerous, true, "Large image trap should flag");
assert.ok(imageTrapLarge.confidence >= 70, `imageTrapLarge confidence: ${imageTrapLarge.confidence}`);

// ── Ticket #111767: URL-text mismatch trap ─────────────────────────────────────
// Sender: cusidomitaq08@gmail.com (free webmail)
// The email SHOWS "https://booking.com/complaint?op_token=..." as hyperlink text,
// but the actual href goes to https://publick-gstx.com — a confirmed phishing domain.
// Two checks: (1) publick-gstx.com is now a known trap host → confidence 98
//             (2) Even for an unknown domain, URL text mismatch alone scores 88.

const knownTrapDirect = analyzeNavigationTarget(
  "https://publick-gstx.com",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/111767",
  { kind: "text-link", label: "" }
);
assert.equal(knownTrapDirect.dangerous, true, "publick-gstx.com should be flagged as a known trap host");
assert.ok(knownTrapDirect.confidence >= 95, `knownTrapDirect confidence: ${knownTrapDirect.confidence}`);

const urlMismatchTrap = analyzeNavigationTarget(
  "https://some-random-phishing-domain.ru",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/111767",
  {
    kind: "text-link",
    label: "https://booking.com/complaint?op_token=eeceba7d-e04f-4857-bb09-3d3e86893748",
    ticket: {
      senderEmail: "cusidomitaq08@gmail.com",
      subject: "Special Needs Room Booking",
      senderDisplayName: "Adriene R"
    }
  }
);
assert.equal(urlMismatchTrap.dangerous, true, "Link showing booking.com but going to phishing domain should be flagged");
assert.ok(urlMismatchTrap.confidence >= 80, `urlMismatchTrap confidence: ${urlMismatchTrap.confidence}`);

// ── Ticket #124539: "Complaint received about your hotel" ──────────────────────
// Sender: wordpress@berkemeier-recht.de (compromised WordPress site, NOT free webmail)
// Button: "View feedback details" → https://raise-payment-flip-decorate.s3.amazonaws.com/
// Two signals should fire: CTA button keyword "view feedback" + third-party brand impersonation.

const viewFeedbackCtaTest = analyzeNavigationTarget(
  "https://raise-payment-flip-decorate.s3.amazonaws.com/y/yx8rq",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/124539",
  {
    kind: "button-link",
    label: "View feedback details",
    buttonStyled: true,
    ticket: {
      senderEmail: "wordpress@berkemeier-recht.de",
      subject: "Complaint received about your hotel",
      senderDisplayName: "Felix Braun"
    }
  }
);
assert.equal(viewFeedbackCtaTest.dangerous, true, '"View feedback details" button to S3 URL should be flagged');
assert.ok(viewFeedbackCtaTest.confidence >= 70, `viewFeedbackCtaTest confidence: ${viewFeedbackCtaTest.confidence}`);

// Verify the CTA label matching is case-insensitive
assert.equal(isSuspiciousCtaLabel("View feedback details"), true, '"View feedback details" should be a suspicious CTA label');
assert.equal(isSuspiciousCtaLabel("View feedback"), true, '"View feedback" should be a suspicious CTA label');
assert.equal(isSuspiciousCtaLabel("See details"), true, '"See details" should be a suspicious CTA label');
assert.equal(isSuspiciousCtaLabel("Take action"), true, '"Take action" should be a suspicious CTA label');

// ── Ticket #148736: Booking.com VCC phishing via search.app redirect ───────────
// Sender: info@samartpeyzaj.com impersonating Booking.com.
// Button "Review and respond" links to https://search.app/CHSyV (Google link-redirect
// that hides the true destination). search.app is now a known trap host.

const searchAppTrap = analyzeNavigationTarget(
  "https://search.app/CHSyV",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/148736",
  {
    kind: "button-link",
    label: "Review and respond",
    buttonStyled: true,
    ticket: {
      senderEmail: "info@samartpeyzaj.com",
      subject: "Service Message: (5704682931)",
      senderDisplayName: "Extranet"
    }
  }
);
assert.equal(searchAppTrap.dangerous, true, "search.app redirect should be flagged as a trap host");
assert.ok(searchAppTrap.confidence >= 95, `searchAppTrap confidence: ${searchAppTrap.confidence}`);
assert.equal(checkDownloadTrapHost("search.app").dangerous, true, "search.app should be a known trap host");

// ── Ticket #150428: generalizing brand-impersonation + external CTA ─────────────
// Sender: phil@circleminc.com (display "Booking.com Message") impersonating Booking.com.
// Button "Process cancellation" → https://jinsureongo.net (a NEW domain, NOT hardcoded).
// Must be caught by the generalizing combo signal, not a trap-host list.

const newUnknownDomainTrap = analyzeNavigationTarget(
  "https://jinsureongo.net",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/150428",
  {
    kind: "button-link",
    label: "Process cancellation",
    buttonStyled: true,
    ticket: {
      senderEmail: "phil@circleminc.com",
      subject: "Booking.com - We have new guest message! #5204849431",
      senderDisplayName: "Booking.com Message"
    }
  }
);
assert.equal(newUnknownDomainTrap.dangerous, true, "Brand impersonation + external CTA to a NEW domain should be flagged without hardcoding");
assert.ok(newUnknownDomainTrap.confidence >= 70, `newUnknownDomainTrap confidence: ${newUnknownDomainTrap.confidence}`);

// Generalization check: a button label NOT in the CTA list, brand impersonation + styled button.
const unknownLabelTrap = analyzeNavigationTarget(
  "https://totally-new-evil-domain-xyz.com",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/999999",
  {
    kind: "button-link",
    label: "Открыть детали",   // non-English / unknown label
    buttonStyled: true,
    ticket: {
      senderEmail: "noreply@randomdomain123.ru",
      subject: "Booking.com reservation update",
      senderDisplayName: "Booking.com"
    }
  }
);
assert.equal(unknownLabelTrap.dangerous, true, "Brand impersonation + styled external button with unknown label should still flag");

// False-positive guard: a real hotel whose own domain matches its brand, plain link.
const legitHotelLink = analyzeNavigationTarget(
  "https://grandhotel.com/booking/confirm",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/5",
  {
    kind: "text-link",
    label: "View your reservation",
    ticket: {
      senderEmail: "reservations@grandhotel.com",
      subject: "Your hotel reservation",
      senderDisplayName: "Grand Hotel"
    }
  }
);
assert.equal(legitHotelLink.dangerous, false, "Legit hotel whose domain matches its brand should not be flagged");

// False-positive guard: Perk is a CBS partner and uses perk.go.link app/deep links.
// The email can contain a large clickable QR/banner image, but this partner host
// should not be treated like an unknown image trap.
const legitPerkPartnerLink = analyzeNavigationTarget(
  "https://perk.go.link/6XJB4",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/237447",
  {
    kind: "image-link",
    label: "Scan the code or click here to download the app",
    imgSrc: "https://perk.com/assets/app-banner.png",
    imgWidth: 403,
    imgHeight: 167,
    ticket: {
      senderEmail: "support@perk.com",
      subject: "[Perk] Re: Claim invoice for reservation 678140900",
      senderDisplayName: "Perk"
    }
  }
);
assert.equal(legitPerkPartnerLink.dangerous, false, "Perk partner app link should not be flagged");

// Real booking.com link from real booking.com address should NOT flag
const realBookingLink = analyzeNavigationTarget(
  "https://booking.com/complaint?op_token=abc123",
  "support.stayzltd.com",
  "https://support.stayzltd.com/agent/tickets/details/1",
  {
    kind: "text-link",
    label: "https://booking.com/complaint?op_token=abc123"
  }
);
assert.equal(realBookingLink.dangerous, false, "Genuine booking.com link should not flag");

console.log("analysis.test.mjs: all passed");
