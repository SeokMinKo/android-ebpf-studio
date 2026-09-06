// Counts completion records independently of the app and checks native whole-
// session coverage. Optional oracle is for a labeled known-path fixture only.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";
import { spawn, execFile } from "node:child_process";

const [exe, session, output, theme = "light", oraclePath] = process.argv.slice(2);
if (!exe || !session || !output || !["light", "dark", "contrast"].includes(theme)) {
  throw new Error("Usage: node check-filepath-coverage.mjs <exe> <session.ndjson> <new-output-dir> [light|dark|contrast] [known-fixture-oracle.json]");
}
const digest = async p => {
  const hash = crypto.createHash("sha256");
  for await (const chunk of fs.createReadStream(p)) hash.update(chunk);
  return hash.digest("hex");
};
const source = path.resolve(session), dir = path.resolve(output);
const before = await digest(source);
let completions = 0, observations = 0, observationBytes = 0;
for await (const line of readline.createInterface({ input: fs.createReadStream(source), crlfDelay: Infinity })) {
  if (!line.trim()) continue;
  const record = JSON.parse(line);
  if (record.event?.kind === "block_complete") completions++;
  if (record.event?.kind === "observed_block_completion") {
    completions++; observations++;
    observationBytes += record.event.data.issue.bytes;
  }
}
if (!completions || !Number.isSafeInteger(observationBytes)) throw new Error("Use nonempty, valid storage-event input with exactly representable byte totals");
fs.mkdirSync(dir);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("ANDROID_EBPF_QA_")));
Object.assign(env, {
  ANDROID_EBPF_QA_OUTPUT: path.join(dir, "coverage.png"), ANDROID_EBPF_QA_SESSION: source,
  ANDROID_EBPF_QA_PAGE: "overview", ANDROID_EBPF_QA_THEME: theme,
  ANDROID_EBPF_QA_GESTURE: "coverage-basis", ANDROID_EBPF_QA_SCALE: "1",
});
const child = spawn(path.resolve(exe), [], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
let peakWorkingSetKiB = null, memorySamples = 0;
const memoryTimer = process.platform === "win32" ? setInterval(() => {
  execFile("tasklist.exe", ["/FI", `PID eq ${child.pid}`, "/FO", "CSV", "/NH"], { windowsHide: true }, (error, data) => {
    if (error) return;
    const fields = data.trim().split('\",\"');
    if (fields.length < 5) return;
    const kib = Number(fields[4].replace(/[^0-9]/g, ""));
    if (kib > 0) { peakWorkingSetKiB = Math.max(peakWorkingSetKiB ?? 0, kib); memorySamples++; }
  });
}, 500) : null;
child.stdout.on("data", d => log += d);
child.stderr.on("data", d => log += d);
const timer = setTimeout(() => child.kill(), 30000);
const status = await new Promise((resolve, reject) => {
  child.on("error", reject);
  child.on("exit", (code, signal) => resolve({ code, signal }));
}).finally(() => { clearTimeout(timer); if (memoryTimer) clearInterval(memoryTimer); });
fs.writeFileSync(path.join(dir, "process.log"), log);
const d = JSON.parse(fs.readFileSync(path.join(dir, "coverage.json")));
const c = d.session_file_path_coverage;
const count = c.exact.count + c.probable.count + c.unresolved.count;
const oracle = oraclePath ? JSON.parse(fs.readFileSync(oraclePath)) : null;
const checks = {
  process: status.code === 0 && status.signal === null,
  ready: d.phase === "Complete" && !d.qa_timed_out && d.qa_input_step === 7,
  whole_denominator: count === completions,
  unresolved_partition: c.unresolved.count === c.no_origin + c.missing_path + c.context_only + c.incomplete_origin_set + c.observation_without_file_identity + c.unmatched_completions,
  observation_volume: observations !== completions || (c.unresolved.count === observations && c.unresolved.known_bytes === observationBytes),
  known_fixture: !oracle || Object.entries(oracle).every(([key, value]) => JSON.stringify(c[key]) === JSON.stringify(value)),
  performance: d.reanalysis_ms < 5000,
  source_preserved: await digest(source) === before,
  screenshot: fs.statSync(path.join(dir, "coverage.png")).size > 0,
};
fs.writeFileSync(path.join(dir, "verdict.json"), JSON.stringify({ checks, status, source_sha256: before, exe_sha256: await digest(exe), independently_counted_completions: completions, coverage: c, load_and_coverage_ms: d.reanalysis_ms, ui_performance: d.ui_performance, memory: { sampled_peak_working_set_kib: peakWorkingSetKiB, samples: memorySamples, interval_ms: 500 }, evidence: "saved-data native rendering; expanded disclosure is a QA preset, not a click transition; excludes ADB and capture finalization" }, null, 2));
if (Object.values(checks).some(v => !v)) throw new Error(JSON.stringify(checks));
console.log(JSON.stringify(checks));
