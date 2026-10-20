// Isometric projection kernel from the iso-glow skill (MIT, April Zhu), which builds on
// iso-figure by Tolga Cohce (MIT, github.com/MrBongoC/ai-iso-skill). Copied unchanged.
const ISO = (() => {
  const C = Math.cos(Math.PI / 6), S = Math.sin(Math.PI / 6);
  function kernel(OX, OY) {
    const P = (x,y,z) => [(x-y)*C + OX, (x+y)*S - z + OY];
    const D = (x,y,z) => [(x-y)*C, (x+y)*S - z];
    const plane = (O,U,V) => { const o=P(...O), u=D(...U), v=D(...V);
      return `matrix(${u[0]} ${u[1]} ${v[0]} ${v[1]} ${o[0]} ${o[1]})`; };
    const TOP   = (x,y,z) => plane([x,y,z],[1,0,0],[0,1,0]);
    const FRONT = (x,y,z) => plane([x,y,z],[1,0,0],[0,0,-1]);
    const SIDE  = (x,y,z) => plane([x,y,z],[0,-1,0],[0,0,-1]);
    const rect = (t,w,h,r=0,cls='face') => `<g transform="${t}"><rect class="${cls}" width="${w}" height="${h}" rx="${r}"/></g>`;
    // Rounded box: one rounded top plus one continuous side wall along the visible part of the
    // outline, so the corners meet cleanly. r = 0 keeps the classic three flat faces.
    const rounded = (x,y,z,w,d,h,r,cls) => {
      r = Math.min(r, w/2, d/2);
      const n = 10, z1 = z + h, q = Math.PI/4, H = Math.PI/2, c = cls ? ' ' + cls : '';
      const arc = (cx,cy,a0,a1) => { const o = []; for (let i = 0; i <= n; i++) { const a = a0 + (a1-a0)*i/n; o.push([cx + r*Math.cos(a), cy + r*Math.sin(a)]); } return o; };
      const ring = [...arc(x+w-r,y+r,-H,0), ...arc(x+w-r,y+d-r,0,H), ...arc(x+r,y+d-r,H,2*H), ...arc(x+r,y+r,2*H,3*H)];
      const vis  = [...arc(x+w-r,y+r,-q,0), ...arc(x+w-r,y+d-r,0,H), ...arc(x+r,y+d-r,H,3*q)];
      const d3 = pts => 'M' + pts.map(p => P(...p).map(v => v.toFixed(2)).join(' ')).join('L') + 'Z';
      const wall = [...vis.map(([a,b]) => [a,b,z]), ...vis.slice().reverse().map(([a,b]) => [a,b,z1])];
      return `<path class="face${c}" d="${d3(wall)}"/><path class="face top${c}" d="${d3(ring.map(([a,b]) => [a,b,z1]))}"/>`;
    };
    const box = (x,y,z,w,d,h,r=0) => r > 0 ? rounded(x,y,z,w,d,h,r,'') :
      rect(SIDE(x+w,y+d,z+h), d,h) + rect(FRONT(x,y+d,z+h), w,h) + rect(TOP(x,y,z+h), w,d,0,'face top');
    const boxc = (x,y,z,w,d,h,r,cls) => r > 0 ? rounded(x,y,z,w,d,h,r,cls) :
      rect(SIDE(x+w,y+d,z+h), d,h,0,'face '+cls) + rect(FRONT(x,y+d,z+h), w,h,0,'face '+cls) + rect(TOP(x,y,z+h), w,d,0,'face top '+cls);
    // 3D polyline -> SVG path "d"
    const path = pts => 'M' + pts.map(p => P(...p).map(n => n.toFixed(2)).join(' ')).join('L');
    return { C, S, P, D, plane, TOP, FRONT, SIDE, rect, box, boxc, path };
  }
  // Frame a scene: pass its extreme 3D corners. Returns kernel + viewBox padded to ~4:3.
  function frame(points, margin = 0.09, aspect = 4 / 3) {
    const d = points.map(([x,y,z]) => [(x-y)*C, (x+y)*S - z]);
    let x0 = Math.min(...d.map(p => p[0])), x1 = Math.max(...d.map(p => p[0]));
    let y0 = Math.min(...d.map(p => p[1])), y1 = Math.max(...d.map(p => p[1]));
    const m = margin * Math.max(x1 - x0, y1 - y0);
    let w = x1 - x0 + 2*m, h = y1 - y0 + 2*m;
    let ox = m - x0, oy = m - y0;
    if (w / h < aspect) { const nw = h * aspect; ox += (nw - w) / 2; w = nw; }
    else { const nh = w / aspect; oy += (nh - h) / 2; h = nh; }
    return { ...kernel(ox, oy), viewBox: `0 0 ${w.toFixed(1)} ${h.toFixed(1)}`, W: w, H: h };
  }
  // repeated detail lines in a face-local group
  const slits = (a0, a1, step, b0, b1, vertical = true, cls = 'detail') => {
    let s = ''; for (let a = a0; a <= a1 + 1e-6; a += step)
      s += vertical ? `<line class="${cls}" x1="${a}" y1="${b0}" x2="${a}" y2="${b1}"/>` : `<line class="${cls}" x1="${b0}" y1="${a}" x2="${b1}" y2="${a}"/>`;
    return s;
  };
  const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  return { kernel, frame, slits, esc };
})();
module.exports = ISO;
