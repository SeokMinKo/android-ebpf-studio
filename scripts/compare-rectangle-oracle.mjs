import fs from 'node:fs';
const parseExact = text => JSON.parse(text, (_k,v,c) => typeof v === 'number' && /^\d+$/.test(c?.source ?? '') && !Number.isSafeInteger(v) ? c.source : v);
// Independent raw pairing and rectangle membership; no application analysis imports.
export function rectangleOracle(source, pane, rectangle) {
  const pending = new Map(), ambiguous = new Map(), rows = [];
  let origin = Infinity;
  for (const line of fs.readFileSync(source, 'utf8').trim().split(/\r?\n/)) {
    const e = parseExact(line).event, d = e?.data;
    if (!d) continue;
    const t = d.ts_ns ?? d.start_ts_ns;
    if (typeof t === 'number') origin = Math.min(origin, t);
    // Lifetime expiry happens at block insert/issue/complete, not unrelated clock domains.
    if (['block_insert','block_issue','block_complete'].includes(e.kind)) {
      for (const [key, value] of pending) if (d.ts_ns-value.ts_ns > 30e9) pending.delete(key);
      for (const [key, ts] of ambiguous) if (d.ts_ns-ts > 30e9) ambiguous.delete(key);
    }
    const id = [d.request_id, d.device_major, d.device_minor].join(':');
    if (e.kind === 'block_issue') {
      if (pending.has(id) || ambiguous.has(id)) { ambiguous.set(id, d.ts_ns); pending.delete(id); }
      else pending.set(id, d);
    }
    if (e.kind === 'block_complete') {
      const i = pending.get(id); pending.delete(id);
      if (ambiguous.delete(id) || !i || d.ts_ns < i.ts_ns || d.ts_ns-i.ts_ns > 30e9) continue;
      rows.push({ key: [String(i.request_id), String(i.ts_ns), String(i.device_major), String(i.device_minor)], end: d.ts_ns, sector: i.sector, bytes: i.bytes, op: i.operation });
    }
  }
  const selected = rows.filter(r => {
    const x = (r.end-origin)/1e6, y = r.sector*512/1e6;
    return x >= rectangle[0][0] && x <= rectangle[1][0] && y >= rectangle[0][1] && y <= rectangle[1][1];
  });
  const normalize = keys => keys.map(k => k.map(String).join(':')).sort();
  const expected = { count: selected.length, keys: normalize(selected.map(r=>r.key)), read_bytes: selected.filter(r=>r.op==='read').reduce((n,r)=>n+r.bytes,0), write_bytes: selected.filter(r=>r.op==='write').reduce((n,r)=>n+r.bytes,0) };
  return { expected, actual: { count:pane.selected, keys:normalize(pane.selected_keys??[]), read_bytes:pane.read_bytes, write_bytes:pane.write_bytes }, origin, origin_matches:origin===pane.origin_ns, axes_supported:JSON.stringify(pane.axes)===JSON.stringify(['Time (ms)','Address (MB)']) };
}
