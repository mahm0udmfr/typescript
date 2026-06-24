import { mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const source = join(root, "src", "cbs-hunter-logo.png");
const iconsDir = join(root, "icons");

if (!existsSync(source)) {
  console.error("Missing src/cbs-hunter-logo.png — cannot generate extension icons.");
  process.exit(1);
}

mkdirSync(iconsDir, { recursive: true });

const sizes = [16, 48, 128];

for (const size of sizes) {
  await sharp(source)
    .resize(size, size, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 1 }
    })
    .png()
    .toFile(join(iconsDir, `icon${size}.png`));
}

console.log(`Generated icons from cbs-hunter-logo.png → ${sizes.map((s) => `icon${s}.png`).join(", ")}`);
