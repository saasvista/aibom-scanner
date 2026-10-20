FIGS.push({
  id: 'ab', name: 'aibom-scanner', hint: 'Space or Scan runs it - t / j / s pick the output - click a layer',
  aria: 'Exploded isometric diagram of the aibom-scanner pipeline: repo walk, detectors, risk engine, control map and formatters. Press space or the Scan key to run a scan; each layer lights in order. Keys t, j and s pick table, JSON or SARIF output.',
  mount(stage, api) {
    const esc = api.iso.esc;
    const K = api.iso.frame([[0,0,0],[300,0,0],[0,230,0],[300,230,0],[20,20,270],[240,20,270],[20,160,270]]);
    const { P, TOP, FRONT, SIDE, box } = K;
    const W = 220, Dp = 140, H = 26, X0 = 20, Y0 = 20, RX = 256, RY = 36;
    const LAYERS = [
      { name: '02 DETECTORS',  cells: ['AI SDK', 'MCP', 'TOOLS', 'DEV', 'SECRETS'],
        read: 'detectors - sdk imports + deps, mcp servers, tool capabilities, dev tools, secrets' },
      { name: '03 RISK ENGINE', cells: ['CLASSIFY', 'CONSOLIDATE', 'EVIDENCE'],
        read: 'risk engine - classify, merge duplicates, mark documented vs inferred' },
      { name: '04 CONTROL MAP', cells: ['NIST RMF', 'ISO42001', 'EU AI ACT', 'OWASP LLM', 'AGENTIC'],
        read: 'control map - nist ai rmf, iso 42001, eu ai act, owasp llm + agentic' },
      { name: '05 FORMATTERS', cells: ['TABLE', 'JSON', 'SARIF'],
        read: 'formatters - table for people, json for pipelines, sarif for code scanning' },
    ];
    const FMTS = ['table', 'json', 'sarif'];
    const zOf = i => 40 + i * 66;                 // slab bottom
    const zMid = i => zOf(i) + H / 2;
    const TOPZ = zOf(LAYERS.length - 1) + H;
    const line = pts => 'M' + pts.map(p => P(...p).map(n => n.toFixed(2)).join(' ')).join(' L');

    let svg = '';
    // 01 repo walk: ground plate with file tiles in the front strip
    svg += box(0, 0, 0, 300, 230, 8, 12);
    svg += `<g transform="${TOP(0, 0, 8)}">`;
    svg += `<rect class="detail" x="8" y="8" width="284" height="214" rx="8"/>`;
    svg += `<text class="label" x="22" y="172" font-size="7.5">01 REPO WALK</text>`;
    for (let i = 0; i < 12; i++) {
      const c = i % 6, r = Math.floor(i / 6);
      svg += `<rect id="ab-t${i}" class="glass" x="${22 + c * 26}" y="${178 + r * 22}" width="20" height="16" rx="2"/>`;
    }
    svg += `</g>`;

    // slabs, bottom to top
    LAYERS.forEach((L, i) => {
      const z = zOf(i), n = L.cells.length, fs = n > 3 ? 6 : 7;
      svg += `<g class="press" id="ab-L${i}">`;
      svg += box(X0, Y0, z, W, Dp, H, 6);
      // front face: one glass cell per part
      svg += `<g transform="${FRONT(X0, Y0 + Dp, z + H)}">`;
      const gap = 4, cw = (W - 12 - gap * (n - 1)) / n;
      L.cells.forEach((name, k) => {
        const x = 6 + k * (cw + gap);
        svg += `<rect id="ab-c${i}-${k}" class="glass" x="${x.toFixed(1)}" y="5" width="${cw.toFixed(1)}" height="16" rx="2"/>`;
        svg += `<text id="ab-x${i}-${k}" class="label" x="${(x + cw / 2).toFixed(1)}" y="15.6" font-size="${fs}" text-anchor="middle">${esc(name)}</text>`;
      });
      svg += `</g>`;
      // side face: layer name, vents, status led
      svg += `<g transform="${SIDE(X0 + W, Y0 + Dp, z + H)}">`;
      svg += `<text class="label" x="8" y="16" font-size="7.5">${esc(L.name)}</text>`;
      svg += api.iso.slits(88, 116, 4, 6, 20, true, 'detail');
      svg += `<rect id="ab-led${i}" class="led" x="130" y="10" width="5" height="5" rx="1"/>`;
      svg += `</g>`;
      svg += `</g>`;
    });

    // output tiles and halo on the top face of the formatter slab
    svg += `<g transform="${TOP(X0, Y0, TOPZ)}">`;
    svg += `<rect id="ab-halo" class="halo" filter="url(#bloom)" x="20" y="30" width="180" height="90" rx="20"/>`;
    svg += `<text class="label" x="12" y="18" font-size="8">aibom-scanner scan --path .</text>`;
    FMTS.forEach((f, k) => {
      const x = 14 + k * 68;
      svg += `<g class="press" id="ab-f${k}"><rect id="ab-g${k}" class="glass" x="${x}" y="34" width="60" height="80" rx="4"/>`;
      svg += `<text id="ab-s${k}" class="label" x="${x + 30}" y="70" font-size="11" text-anchor="middle">${f.toUpperCase()}</text>`;
      svg += `<text id="ab-n${k}" class="label" x="${x + 30}" y="88" font-size="6.5" text-anchor="middle">-f ${f}</text></g>`;
    });
    svg += `</g>`;

    // the scan key on the plate, front right
    svg += `<g class="press" id="ab-run">${box(206, 196, 8, 64, 22, 8, 4)}</g>`;
    svg += `<g transform="${TOP(206, 196, 16)}"><text id="ab-runt" class="label" x="32" y="14" font-size="8" text-anchor="middle">SCAN</text></g>`;

    // riser cable on the right with taps into each slab
    const riser = [[RX, RY, 8], [RX, RY, zMid(LAYERS.length - 1)]];
    svg += `<path class="wire-under" d="${line(riser)}"/>`;
    svg += `<path id="ab-w" class="wire" d="${line(riser)}"/>`;
    LAYERS.forEach((L, i) => {
      const tap = [[RX, RY, zMid(i)], [X0 + W, RY, zMid(i)]];
      svg += `<path id="ab-wt${i}" class="wire" d="${line(tap)}"/>`;
      const seg = [[RX, RY, i ? zMid(i - 1) : 8], [RX, RY, zMid(i)], [X0 + W, RY, zMid(i)]];
      svg += `<path id="ab-p${i}" class="pulse" pathLength="1000" d="${line(seg)}"/>`;
    });

    stage.setAttribute('viewBox', K.viewBox);
    stage.innerHTML = svg;
    const $ = id => stage.querySelector('#' + id);

    const st = { tiles: 0, cells: LAYERS.map(() => 0), wire: -1, fmt: 2, done: false, run: 0, focus: -1 };

    function render() {
      for (let i = 0; i < 12; i++) $('ab-t' + i).classList.toggle('hot', i < st.tiles);
      LAYERS.forEach((L, i) => {
        L.cells.forEach((_, k) => {
          let on = k < st.cells[i];
          if (i === LAYERS.length - 1) on = st.done && k === st.fmt;
          $(`ab-c${i}-${k}`).classList.toggle('hot', on);
          $(`ab-x${i}-${k}`).setAttribute('class', on ? 'scr' : 'label');
        });
        $('ab-led' + i).classList.toggle('hot', st.cells[i] > 0 || (i === LAYERS.length - 1 && st.done));
        $('ab-wt' + i).classList.toggle('hot', st.wire >= i);
        $('ab-L' + i).classList.toggle('latched', st.focus === i);
      });
      $('ab-w').classList.toggle('hot', st.wire >= 0);
      FMTS.forEach((_, k) => {
        const on = st.done && k === st.fmt;
        $('ab-g' + k).classList.toggle('hot', on);
        $('ab-s' + k).setAttribute('class', on ? 'scr' : 'label');
        $('ab-n' + k).setAttribute('class', on ? 'scr-accent' : 'label');
      });
      $('ab-halo').classList.toggle('hot', st.done);
      $('ab-runt').setAttribute('class', st.wire >= 0 && !st.done ? 'scr' : 'label');
      api.power(st.tiles > 0);
    }

    function reset() {
      st.run++; st.tiles = 0; st.cells = LAYERS.map(() => 0); st.wire = -1; st.done = false; st.focus = -1;
      render(); api.readout('ready - press space to scan');
    }

    function scan() {
      reset();
      const run = st.run;
      const go = (ms, fn) => api.after(ms, () => { if (run === st.run) fn(); });
      api.flash($('ab-run'));
      let t = 0;
      for (let i = 1; i <= 12; i++) go(t += 60, () => { st.tiles = i; render(); api.readout(`walking files - ${i * 37}`); });
      LAYERS.forEach((L, li) => {
        go(t += 220, () => { st.wire = li; render(); api.replay($('ab-p' + li), 'go'); });
        t += 380;
        if (li === LAYERS.length - 1) {
          go(t, () => { st.done = true; st.cells[li] = 1; render(); api.readout(`done - ${FMTS[st.fmt]} report written`); });
          return;
        }
        L.cells.forEach((name, k) => go(t += 150, () => {
          st.cells[li] = k + 1; render(); api.readout(`${L.name.slice(3).toLowerCase()} - ${name.toLowerCase()}`);
        }));
      });
    }

    function pickFormat(k) {
      st.fmt = k; render();
      api.readout(st.done ? `done - ${FMTS[k]} report written` : `output - ${FMTS[k]}`);
      if (st.done) api.flash($('ab-f' + k));
    }

    function focusLayer(i) {
      st.focus = st.focus === i ? -1 : i; render();
      api.readout(st.focus === i ? LAYERS[i].read : (st.done ? `done - ${FMTS[st.fmt]} report written` : 'ready - press space to scan'));
    }

    stage.addEventListener('click', e => {
      if (e.target.closest('#ab-run')) return scan();
      const f = e.target.closest('[id^="ab-f"]');
      if (f) return pickFormat(+f.id.slice(4));
      const l = e.target.closest('[id^="ab-L"]');
      if (l) focusLayer(+l.id.slice(4));
    });

    reset();
    return {
      key: e => {
        if (e.key === ' ' || e.key === 'Enter') { scan(); return true; }
        const k = { t: 0, j: 1, s: 2 }[e.key.toLowerCase()];
        if (k !== undefined) { pickFormat(k); return true; }
        if (e.key === 'r') { reset(); return true; }
        return false;
      },
      demo: () => api.after(300, scan),
    };
  },
});
