import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");

mkdirSync(dist, { recursive: true });

copyFileSync(join(root, "manifest.json"), join(dist, "manifest.json"));
copyFileSync(join(root, "src", "warning.css"), join(dist, "warning.css"));
copyFileSync(join(root, "src", "popup.html"), join(dist, "popup.html"));

console.log("Built → dist/  (Load unpacked in Chrome/Edge)");
