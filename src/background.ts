/** Service worker — reserved for future use (badge, logging, etc.) */

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "DOWNLOAD_TRAP_DETECTED") {
    console.info("[Download Trap Guard]", message.count, "risky image(s) on", message.url);
  }
});
