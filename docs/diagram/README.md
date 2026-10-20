# Pipeline diagram

`docs/pipeline.svg` is the animated diagram in the main README's "How It Works" section. It plays one scan on a
loop: the repo walk, the detectors, the risk engine, the control mapper, then the report. It uses CSS animation
only, because GitHub strips scripts from images. Viewers who ask for reduced motion get the finished frame.

To change it, edit `fig.js` and rebuild from the repository root:

```bash
node docs/diagram/build.js
```

`build.js` runs `fig.js` once with a simulated clock, records when each part lights up, and writes those times
into the SVG as `@keyframes`. It needs Node.js and nothing else.

`kernel.js` (the isometric projection) and the drawing style come from the iso-glow skill by April Zhu, which
builds on iso-figure by Tolga Cohce. Both are MIT licensed; the notice is in `LICENSE-iso-glow.txt`.
