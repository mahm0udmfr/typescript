import { copyFileSync, mkdirSync, cpSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
// The full-size logo is only the source for the icons; the extension ships the small copy.
copyFileSync(join(root, "src", "cbs-hunter-logo-small.png"), join(dist, "cbs-hunter-logo-small.png"));
rmSync(join(dist, "cbs-hunter-logo.png"), { force: true });

const iconsSrc = join(root, "icons");
const iconsDist = join(dist, "icons");
if (existsSync(iconsSrc)) {
  mkdirSync(iconsDist, { recursive: true });
  cpSync(iconsSrc, iconsDist, { recursive: true });
}

// Chrome classic content scripts cannot use `export` — keep ESM copy for tests.
// Both files are wrapped in guard IIFEs so a repeat injection doesn't cause
// "already been declared" SyntaxErrors or duplicate listeners.
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
writeFileSync(
  contentPath,
  `;(function(){if(globalThis.__dtgContentLoaded)return;globalThis.__dtgContentLoaded=true;\n${contentSrc}\n})();\n`
);

console.log("Built → dist/  (Load unpacked in Chrome/Edge)");
