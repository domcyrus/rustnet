#!/usr/bin/env node
// Regenerate the packaged artwork from assets/rustnet.svg.
// Setup and output details: resources/packaging/README.md.
const fs = require('node:fs/promises');
const path = require('node:path');
const sharp = require('sharp');

const root = path.resolve(__dirname, '..');
const packaging = 'resources/packaging';
const icoSizes = [16, 24, 32, 48, 64, 128, 256];
// PNG-backed standard and Retina representations supported by modern macOS.
const icnsSizes = [
  ['icp4', 16], ['icp5', 32], ['icp6', 64], ['ic07', 128],
  ['ic08', 256], ['ic09', 512], ['ic10', 1024],
  ['ic11', 32], ['ic12', 64], ['ic13', 256], ['ic14', 512],
];

async function write(relative, data) {
  await fs.writeFile(path.join(root, relative), data);
  console.log(relative);
}

function svg(width, height, contents) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">\n${contents}\n</svg>\n`;
}

async function png(source, width, height = width) {
  // Rasterize above the target resolution so small strokes stay smooth.
  return sharp(Buffer.from(source), { density: 288 })
    .resize(width, height)
    .png({ compressionLevel: 9 })
    .toBuffer();
}

function ico(images) {
  const header = Buffer.alloc(6 + 16 * images.length);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach(({ size, data }, index) => {
    const entry = 6 + index * 16;
    header[entry] = size === 256 ? 0 : size;
    header[entry + 1] = header[entry];
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(data.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    offset += data.length;
  });
  return Buffer.concat([header, ...images.map(({ data }) => data)]);
}

function icns(images) {
  const chunks = images.map(({ type, data }) => {
    const header = Buffer.alloc(8);
    header.write(type, 0, 4, 'ascii');
    header.writeUInt32BE(data.length + 8, 4);
    return Buffer.concat([header, data]);
  });
  const header = Buffer.alloc(8);
  header.write('icns', 0, 4, 'ascii');
  header.writeUInt32BE(8 + chunks.reduce((sum, chunk) => sum + chunk.length, 0), 4);
  return Buffer.concat([header, ...chunks]);
}

async function main() {
  const master = await fs.readFile(path.join(root, 'assets/rustnet.svg'), 'utf8');
  // Nest the SVG directly: every export retains the master's geometry/colors.
  const mark = master.trim();
  const desktop = svg(512, 512, `  <title>RustNet</title>
  <defs>
    <linearGradient id="tile" x2="0" y2="1">
      <stop stop-color="#1c2531"/>
      <stop offset="1" stop-color="#111827"/>
    </linearGradient>
  </defs>
  <rect x="25" y="25" width="462" height="462" rx="104" fill="url(#tile)" stroke="#374151" stroke-width="2"/>
  <g transform="translate(27 36) scale(.86)">${mark}</g>`);
  await write(`${packaging}/linux/graphics/rustnet.svg`, desktop);

  const sizes = [...new Set([...icoSizes, ...icnsSizes.map(([, size]) => size)])];
  const rendered = new Map();
  for (const size of sizes) rendered.set(size, await png(desktop, size));
  await write(`${packaging}/linux/graphics/rustnet.png`, rendered.get(256));
  await write(`${packaging}/macos/graphics/rustnet.png`, rendered.get(1024));
  await write(`${packaging}/windows/graphics/rustnet.ico`, ico(
    icoSizes.map(size => ({ size, data: rendered.get(size) })),
  ));
  await write(`${packaging}/macos/graphics/rustnet.icns`, icns(
    icnsSizes.map(([type, size]) => ({ type, data: rendered.get(size) })),
  ));

  // Matches create-dmg's 900x450 window, with icons at (300,240)/(620,240).
  // No fonts or external images, so exports are independent of installed fonts.
  const background = svg(900, 450, `  <rect width="900" height="450" fill="#f3f4f6"/>
  <g transform="translate(380 -2) scale(.25)">${mark}</g>
  <path d="M 427 240 H 483 M 469 226 L 483 240 L 469 254" fill="none" stroke="#6b7280" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>`);
  await write(`${packaging}/macos/graphics/dmg_bg.png`, await png(background, 900, 450));
}

main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
