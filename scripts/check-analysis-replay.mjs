// Native GUI performance regression. Supply a real, finalized capture; it is read only.
// This measures the post-decode analysis stage, not device Stop/pull/decode time.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';

const [executable, session, destination, budgetArgument = '5000'] = process.argv.slice(2);
const budget = Number(budgetArgument);
if (!executable || !session || !destination || !Number.isFinite(budget) || budget <= 0) {
  throw new Error('Usage: node scripts/check-analysis-replay.mjs <exe> <capture.ndjson> <new-output-directory> [analysis-budget-ms]');
}
const exe = path.resolve(executable), source = path.resolve(session), out = path.resolve(destination);
fs.mkdirSync(out); // Refuse stale reports or overwriting previous evidence.
const hash = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const before = hash(source);
const env = { ...process.env };
for (const key of Object.keys(env)) if (key.startsWith('ANDROID_EBPF_QA_')) delete env[key];
Object.assign(env, {
  ANDROID_EBPF_QA_OUTPUT: path.join(out, 'complete.png'),
  ANDROID_EBPF_QA_GESTURE: 'stream-replay',
  ANDROID_EBPF_QA_STREAM_SESSION: source,
});
const child = spawn(exe, [], { cwd: path.dirname(exe), env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
let log = '', expired = false;
child.stdout.on('data', data => { log += data; });
child.stderr.on('data', data => { log += data; });
const timer = setTimeout(() => { expired = true; child.kill(); }, 120_000);
child.on('error', error => { clearTimeout(timer); console.error(error.message); process.exitCode = 1; });
child.on('close', (code, signal) => {
  clearTimeout(timer);
  fs.writeFileSync(path.join(out, 'app.log'), log);
  let report;
  try { report = JSON.parse(fs.readFileSync(path.join(out, 'complete.json'), 'utf8')); } catch {}
  const checks = {
    complete: code === 0 && !signal && !expired && report?.phase === 'Complete' && !report?.qa_timed_out,
    nonempty: report?.received_events > 0,
    source_unchanged: before === hash(source),
    no_rejected_records: report?.rejected === 0,
    consistent_scope: report?.displayed_summary?.completed_ios === report?.completed_requests
      && report?.trend_request_count === report?.completed_requests,
    analysis_budget: Number.isFinite(report?.stop_analysis_ms) && report.stop_analysis_ms < budget,
  };
  const result = { checks, budget_ms: budget, analysis_ms: report?.stop_analysis_ms,
    received: report?.received_events, retained: report?.completed_requests,
    executable_sha256: hash(exe), source_sha256: before, performance: report?.ui_performance };
  fs.writeFileSync(path.join(out, 'result.json'), JSON.stringify(result, null, 2));
  console.log(JSON.stringify(result, null, 2));
  if (Object.values(checks).some(value => !value)) process.exitCode = 1;
});
