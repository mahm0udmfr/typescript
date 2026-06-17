import { copyFileSync, mkdirSync, cpSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");

mkdirSync(dist, { recursive: true });

spawnSync("node", [join(root, "scripts", "generate-icons.mjs")], { stdio: "inherit" });

copyFileSync(join(root, "manifest.json"), join(dist, "manifest.json"));
copyFileSync(join(root, "src", "warning.css"), join(dist, "warning.css"));
copyFileSync(join(root, "src", "popup.html"), join(dist, "popup.html"));

const iconsSrc = join(root, "icons");
const iconsDist = join(dist, "icons");
if (existsSync(iconsSrc)) {
  mkdirSync(iconsDist, { recursive: true });
  cpSync(iconsSrc, iconsDist, { recursive: true });
}

// Chrome classic content scripts cannot use `export` — keep ESM copy for tests.
// Both files are wrapped in guard IIFEs so re-injection by background.ts
// doesn't cause "already been declared" SyntaxErrors or duplicate listeners.
const analysisPath = join(dist, "analysis.js");
const analysisSrc = readFileSync(analysisPath, "utf8");
writeFileSync(join(dist, "analysis.esm.js"), analysisSrc);
const analysisStripped = analysisSrc.replace(/^export /gm, "");
writeFileSync(
  analysisPath,
  `;(function(){if(globalThis.__dtgAnalysisLoaded)return;globalThis.__dtgAnalysisLoaded=true;\n${analysisStripped}\n})();\n`
);

const contentPath = join(dist, "content.js");
const contentSrc = readFileSync(contentPath, "utf8");
// On re-injection the IIFE exits early but first calls __dtgRescan() so
// background.ts's executeScript triggers a fresh scan after email content loads.
writeFileSync(
  contentPath,
  `;(function(){if(globalThis.__dtgContentLoaded){if(globalThis.__dtgRescan)globalThis.__dtgRescan();return;}globalThis.__dtgContentLoaded=true;\n${contentSrc}\n})();\n`
);

console.log("Built → dist/  (Load unpacked in Chrome/Edge)");
