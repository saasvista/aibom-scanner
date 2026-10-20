// Builds docs/pipeline.svg: the scan sequence from fig.js as a CSS-animated SVG.
// GitHub strips scripts from images but keeps CSS animation, so this runs fig.js once
// against a stub DOM and a simulated clock, records when each part lights up, and
// writes those times into @keyframes. Run from the repo root: node docs/diagram/build.js
const fs = require('fs');
const path = require('path');
const ISO = require('./kernel.js');

const CYCLE = 8000, HOLD_END = 7200, OFF_END = 7500;  // ms: lit until HOLD_END, dark by OFF_END
const COL = {
  panel: '#141516', face: '#17181a', top: '#1b1d1f', line: '#3d4144', detail: '#2b2e30',
  ink: '#868b8f', glass: '#0f1011', glassOn: '#1d1712', accent: '#ffd166',
};

// ---- run the figure against a stub DOM and a simulated clock ----
const FIGS = [];
eval(fs.readFileSync(path.join(__dirname, 'fig.js'), 'utf8'));
let html = '', viewBox = '', now = 0;
const onAt = {};       // id -> first time it lit after the scan started
const pulseAt = {};    // id -> time its pulse was replayed
const markOn = id => { if (now > 0 && !(id in onAt)) onAt[id] = now; };
const els = {};
const el = id => els[id] || (els[id] = {
  classList: { toggle(c, on) { if (on && c === 'hot') markOn(id); } },
  setAttribute(k, v) { if (k === 'class' && /^scr/.test(v)) markOn(id); },
});
const stage = {
  setAttribute(k, v) { if (k === 'viewBox') viewBox = v; },
  set innerHTML(v) { html = v; },
  querySelector: s => el(s.slice(1)),
  addEventListener() {},
};
const queue = [];
const api = {
  iso: { frame: ISO.frame, slits: ISO.slits, esc: ISO.esc },
  readout() {}, power() {}, flash() {}, every() {}, loop() {},
  replay(node) { const id = Object.keys(els).find(k => els[k] === node); if (id) pulseAt[id] = now; },
  after(ms, fn) { queue.push([now + ms, fn]); },
};
const fig = FIGS[0];
const handle = fig.mount(stage, api);
now = 1;                       // anything that lights from here on is part of the scan
handle.demo();
while (queue.length) { queue.sort((a, b) => a[0] - b[0]); const [t, fn] = queue.shift(); now = t; fn(); }

// ---- classify each animated element by its starting class ----
const classOf = id => (html.match(new RegExp(`id="${id}"[^>]*?class="([^"]*)"`)) ||
                       html.match(new RegExp(`class="([^"]*)"[^>]*?id="${id}"`)) || [])[1] || '';
const STATES = {
  glass: [`fill:${COL.glass};stroke:${COL.line}`, `fill:${COL.glassOn};stroke:${COL.accent}`],
  label: [`fill:${COL.ink}`, `fill:${COL.accent}`],
  led:   [`fill:${COL.detail}`, `fill:${COL.accent}`],
  wire:  [`stroke:${COL.line}`, `stroke:${COL.accent}`],
  halo:  ['opacity:0', 'opacity:.22'],
};
const pct = ms => (100 * ms / CYCLE).toFixed(3) + '%';
let css = '';
for (const [id, t] of Object.entries(onAt)) {
  const kind = classOf(id).split(' ')[0];
  const st = STATES[kind];
  if (!st) continue;
  const [off, on] = st;
  css += `@keyframes k-${id}{0%{${off}}${pct(t - 1)}{${off}}${pct(t)}{${on}}${pct(HOLD_END)}{${on}}${pct(OFF_END)}{${off}}100%{${off}}}\n`;
  css += `#${id}{animation:k-${id} ${CYCLE}ms linear infinite}\n`;
}
for (const [id, t] of Object.entries(pulseAt)) {
  const a = 'stroke-dashoffset:70;opacity:0', b = 'stroke-dashoffset:70;opacity:1',
        c = 'stroke-dashoffset:-1000;opacity:1', d = 'stroke-dashoffset:-1000;opacity:0';
  css += `@keyframes k-${id}{0%{${a}}${pct(t - 1)}{${a}}${pct(t)}{${b}}${pct(t + 500)}{${c}}${pct(t + 550)}{${d}}100%{${d}}}\n`;
  css += `#${id}{animation:k-${id} ${CYCLE}ms linear infinite}\n`;
}

const base = `
svg{font-family:"DM Mono",ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.face{fill:${COL.face};stroke:${COL.line};stroke-width:1;stroke-linejoin:round;vector-effect:non-scaling-stroke}
.face.top{fill:${COL.top}}
.detail{fill:none;stroke:${COL.detail};stroke-width:1;vector-effect:non-scaling-stroke}
.label{fill:${COL.ink}}
.glass{fill:${COL.glass};stroke:${COL.line};stroke-width:1;vector-effect:non-scaling-stroke}
.led{fill:${COL.detail}}
.wire{fill:none;stroke:${COL.line};stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;vector-effect:non-scaling-stroke}
.wire-under{fill:none;stroke:${COL.panel};stroke-width:4;stroke-linecap:round}
.pulse{fill:none;stroke:${COL.accent};stroke-width:2.4;stroke-linecap:round;stroke-dasharray:70 1200;stroke-dashoffset:70;opacity:0;vector-effect:non-scaling-stroke}
.halo{fill:${COL.accent};opacity:0}
@media (prefers-reduced-motion:reduce){*{animation-delay:-${HOLD_END - 200}ms!important;animation-play-state:paused!important}}
`;

const [, , vw, vh] = viewBox.split(' ').map(Number);
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${viewBox}" width="${Math.round(vw)}" height="${Math.round(vh)}" role="img" aria-labelledby="t">
<title id="t">aibom-scanner pipeline: repo walk, detectors, risk engine, control map, formatters. A scan lights each layer in turn and ends in a SARIF report.</title>
<defs><filter id="bloom" filterUnits="userSpaceOnUse" x="-200" y="-200" width="${Math.round(vw) + 400}" height="${Math.round(vh) + 400}"><feGaussianBlur stdDeviation="14"/></filter></defs>
<style>${base}${css}</style>
<rect width="100%" height="100%" rx="16" fill="${COL.panel}"/>
${html}
</svg>
`;
const out = path.resolve(process.argv[2] || path.join(__dirname, '..', 'pipeline.svg'));
fs.writeFileSync(out, svg);
console.log(`wrote ${out}: ${svg.length} bytes, ${Object.keys(onAt).length} timed parts, ${Object.keys(pulseAt).length} pulses`);
