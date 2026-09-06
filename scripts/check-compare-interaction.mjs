// Native interaction gate; uses saved sessions and never starts a device capture.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const [exeArg, baselineArg, currentArg, outArg, gesture, scaleArg = '1'] = process.argv.slice(2);
const gestures = ['compare-point', 'compare-area', 'compare-distributions', 'compare-files', 'compare-processes', 'compare-details', 'compare-zoom-back', 'compare-clear'];
if (!exeArg || !baselineArg || !currentArg || !outArg || !gestures.includes(gesture)) {
  throw Error('Usage: node scripts/check-compare-interaction.mjs <exe> <baseline.ndjson> <current.ndjson> <new-output-dir> <compare-gesture> [scale]');
}
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
  ANDROID_EBPF_QA_THEME: 'contrast',
  ANDROID_EBPF_QA_GESTURE: gesture,
  ANDROID_EBPF_QA_SCALE: String(scale),
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
const report = fs.existsSync(json) ? JSON.parse(fs.readFileSync(json, 'utf8')) : null;
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
fs.writeFileSync(path.join(out, 'verdict.json'), JSON.stringify({ gesture, scale, exe_sha256: hash(exe), checks, result, expired }, null, 2));
console.log(JSON.stringify({ gesture, scale, checks }, null, 2));
if (Object.values(checks).some(v => !v)) process.exitCode = 1;
