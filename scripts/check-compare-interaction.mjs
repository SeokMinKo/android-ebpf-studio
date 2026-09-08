// Native interaction gate; uses saved sessions and never starts a device capture.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const parseExact = text => JSON.parse(text, (_k, v, c) => typeof v === 'number' && /^\d+$/.test(c?.source ?? '') && !Number.isSafeInteger(v) ? c.source : v);
const [exeArg, baselineArg, currentArg, outArg, gesture, scaleArg = '1', areaMode = 'empty', theme = 'contrast'] = process.argv.slice(2);
const gestures = ['compare-point', 'compare-percentiles', 'compare-area', 'compare-distributions', 'compare-files', 'compare-processes', 'compare-details', 'compare-zoom-back', 'compare-clear'];
if (!exeArg || !baselineArg || !currentArg || !outArg || !gestures.includes(gesture)) {
  throw Error('Usage: node scripts/check-compare-interaction.mjs <exe> <baseline.ndjson> <current.ndjson> <new-output-dir> <compare-gesture> [scale] [empty|populated] [light|dark|contrast]');
}
if (!['empty', 'populated'].includes(areaMode) || !['light','dark','contrast'].includes(theme)) throw Error('Invalid area mode or theme');
const scale = Number(scaleArg);
if (!Number.isFinite(scale) || scale < 0.5 || scale > 3) throw Error('Scale must be between 0.5 and 3');
const [exe, baseline, current, out] = [exeArg, baselineArg, currentArg, outArg].map(p => path.resolve(p));
if (fs.existsSync(out)) throw Error('Use a new output directory to preserve earlier evidence');
const hash = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const before = [hash(baseline), hash(current)];
fs.mkdirSync(out, { recursive: true });
const env = { ...process.env };
for (const key of Object.keys(env)) if (key.startsWith('ANDROID_EBPF_QA_')) delete env[key];
Object.assign(env, {
  ANDROID_EBPF_QA_OUTPUT: path.join(out, 'compare.png'),
  ANDROID_EBPF_QA_SESSION: current,
  ANDROID_EBPF_QA_BASELINE: baseline,
  ANDROID_EBPF_QA_PAGE: 'compare',
  ANDROID_EBPF_QA_THEME: theme,
  ANDROID_EBPF_QA_GESTURE: gesture,
  ANDROID_EBPF_QA_SCALE: String(scale),
  ANDROID_EBPF_QA_DEPTH: '1',
  ...(areaMode === 'populated' ? { ANDROID_EBPF_QA_AREA_FULL_HEIGHT: '1' } : {}),
});
const child = spawn(exe, [], { env, cwd: path.dirname(exe), windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let log = '', expired = false;
child.stdout.on('data', d => { log += d; });
child.stderr.on('data', d => { log += d; });
const timer = setTimeout(() => { expired = true; child.kill(); }, 30000);
const result = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('exit', (code, signal) => resolve({ code, signal }));
}).finally(() => clearTimeout(timer));
fs.writeFileSync(path.join(out, 'app.log'), log);
const json = path.join(out, 'compare.json');
const report = fs.existsSync(json) ? parseExact(fs.readFileSync(json, 'utf8')) : null;
const c = report?.comparison_explore, a = c?.baseline, b = c?.current;
const checks = {
  exited: result.code === 0 && !result.signal && !expired,
  source_preserved: before[0] === hash(baseline) && before[1] === hash(current),
  interaction_completed: report?.qa_input_step === 7 && !report?.qa_timed_out,
  cohorts_present: a?.retained > 0 && b?.retained > 0 && !c?.error,
  screenshot: fs.existsSync(path.join(out, 'compare.png')),
};
if (gesture === 'compare-point') checks.selection_isolated = a?.selected === 1 && b?.selected === b?.retained;
if (gesture === 'compare-clear') checks.clear_isolated = a?.selected === 0 && b?.selected === b?.retained;
if (gesture === 'compare-zoom-back') checks.restored = a?.zoom_depth === 0 && b?.zoom_depth === 0;

// Independent raw pairing and rectangle membership; no application analysis imports.
function rectangleOracle(source, pane, rectangle) {
  const pending = new Map(), ambiguous = new Set(), rows = [];
  let origin = Infinity;
  for (const line of fs.readFileSync(source, 'utf8').trim().split(/\r?\n/)) {
    const e = parseExact(line).event, d = e?.data;
    if (!d) continue;
    const t = d.ts_ns ?? d.start_ts_ns;
    if (typeof t === 'number') origin = Math.min(origin, t);
    const id = [d.request_id, d.device_major, d.device_minor].join(':');
    if (e.kind === 'block_issue') {
      if (pending.has(id)) { ambiguous.add(id); pending.delete(id); }
      else if (!ambiguous.has(id)) pending.set(id, d);
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
let rectangleAudit;
if (gesture === 'compare-area') {
  checks.rectangle_recorded = Array.isArray(c?.rectangle);
  if (checks.rectangle_recorded) {
    rectangleAudit = [rectangleOracle(baseline,a,c.rectangle), rectangleOracle(current,b,c.rectangle)];
    checks.raw_selection_matches = rectangleAudit.every(v=>v.axes_supported&&v.origin_matches&&JSON.stringify(v.expected)===JSON.stringify(v.actual));
    checks.requested_population = rectangleAudit.every(v=>areaMode==='populated' ? v.expected.count>0 : v.expected.count===0);
    fs.writeFileSync(path.join(out,'rectangle-oracle.json'),JSON.stringify({rectangle:c.rectangle,areaMode,panes:rectangleAudit},null,2));
  }
}

fs.writeFileSync(path.join(out, 'verdict.json'), JSON.stringify({ gesture, scale, exe_sha256: hash(exe), checks, result, expired }, null, 2));
console.log(JSON.stringify({ gesture, scale, checks }, null, 2));
if (Object.values(checks).some(v => !v)) process.exitCode = 1;
