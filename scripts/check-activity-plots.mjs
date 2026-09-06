// Actual native renderer and injected egui input. Saved root block fixtures only;
// this is neither physical-device acceptance nor a GPU/vsync benchmark.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import readline from "node:readline";
import { spawn } from "node:child_process";
const [exeArg, sourceArg, outArg, gesture = "activity-view", theme = "light"] = process.argv.slice(2);
if (!exeArg || !sourceArg || !outArg || !["activity-view", "activity-iops", "activity-throughput", "activity-zoom"].includes(gesture) || !["light", "dark", "contrast"].includes(theme)) {
  throw Error("Usage: node check-activity-plots.mjs <exe> <saved-root-session> <new-output-dir> [activity-view|activity-iops|activity-throughput|activity-zoom] [light|dark|contrast]");
}
const [exe, source, out] = [exeArg, sourceArg, outArg].map(p => path.resolve(p));
const hash = p => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const original = hash(source);
const parseExact = text => JSON.parse(text, (key, value, context) => typeof value === "number" && /^-?\d+$/.test(context?.source ?? "") ? BigInt(context.source) : value);
const pending = new Map(), ios = [];
const id = d => [d.request_id, d.device_major, d.device_minor].join(":");
let sourceCount = 0;
for await (const line of readline.createInterface({input: fs.createReadStream(source), crlfDelay: Infinity})) {
  if (!line.trim()) continue;
  const e = parseExact(line).event, d = e?.data;
  if (!d) continue;
  if (e.kind === "observed_block_completion") throw Error("Use a saved root block fixture; unsupported-clock observations need their separate gate");
  if (e.kind === "block_issue") pending.set(id(d), d);
  if (e.kind === "block_complete") {
    const issue = pending.get(id(d));
    if (issue) {
      ios.push({key: [issue.request_id, issue.ts_ns, issue.device_major, issue.device_minor], completion: d.ts_ns});
      sourceCount++;
      // Independently reproduce the documented detail retention boundary.
      if (ios.length > 100000) ios.splice(0, 10000);
      pending.delete(id(d));
    }
  }
}
if (!ios.length || ios.some(io => io.key.some(v => typeof v !== "bigint"))) throw Error("Nonempty root fixture and Node.js 24+ required");
fs.mkdirSync(out);
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("ANDROID_EBPF_QA_")));
Object.assign(env, {ANDROID_EBPF_QA_OUTPUT: path.join(out, "result.png"), ANDROID_EBPF_QA_SESSION: source, ANDROID_EBPF_QA_PAGE: "overview", ANDROID_EBPF_QA_GESTURE: gesture, ANDROID_EBPF_QA_THEME: theme, ANDROID_EBPF_QA_SCALE: "1"});
const child = spawn(exe, [], {env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"]});
let log = "";
child.stdout.on("data", d => log += d); child.stderr.on("data", d => log += d);
const timer = setTimeout(() => child.kill(), 30000);
const status = await new Promise((resolve, reject) => {child.on("error", reject); child.on("exit", (code, signal) => resolve({code, signal}));}).finally(() => clearTimeout(timer));
fs.writeFileSync(path.join(out, "process.log"), log);
const text = fs.readFileSync(path.join(out, "result.json"), "utf8"), report = JSON.parse(text), exact = parseExact(text), a = report.activity;
const click = ["activity-iops", "activity-throughput"].includes(gesture);
const frame = report.ui_performance.ui_update;
const checks = {
  process: status.code === 0 && status.signal === null,
  input_completed: report.qa_input_step === 7 && !report.qa_timed_out,
  source_preserved: hash(source) === original,
  screenshot: fs.statSync(path.join(out, "result.png")).size > 0,
};
if (click) {
  const second = exact.activity.expected_second, origin = exact.activity.origin_ns;
  const expected = ios.filter(io => io.completion >= origin + second * 1000000000n && io.completion < origin + (second + 1n) * 1000000000n).map(io => JSON.stringify(io.key.map(String))).sort();
  const actual = (exact.activity_selected_keys ?? []).map(k => JSON.stringify(k.map(String))).sort();
  checks.exact_requests = expected.length > 0 && JSON.stringify(actual) === JSON.stringify(expected);
  checks.scope = report.page === "Explore" && report.completed_requests === expected.length && report.selection_count === expected.length;
  checks.time_interval = report.active_filter.start_ms === a.expected_second * 1000 && report.active_filter.end_ms === (a.expected_second + 1) * 1000 - 0.000001;
  checks.response_budget = Number.isFinite(a.elapsed_ms) && a.elapsed_ms < 5000;
} else {
  checks.scope = report.page === "Overview" && report.completed_requests === ios.length && report.trend_request_count === ios.length;
  checks.frame_budget = frame.samples >= 20 && frame.p95_ms <= 16.7;
  if (gesture === "activity-zoom") {
    checks.finer_display = a.width < a.initial_width / 10 && a.mean_spacing < a.initial_spacing;
    checks.response_budget = Number.isFinite(a.elapsed_ms) && a.elapsed_ms < 5000;
  }
}
fs.writeFileSync(path.join(out, "verdict.json"), JSON.stringify({checks, status, gesture, theme, source_count: sourceCount, retained_count: ios.length, activity: a, frame_budget_ms: 16.7, frame, source_sha256: original, exe_sha256: hash(exe)}, null, 2));
console.log(JSON.stringify(checks));
if (Object.values(checks).some(v => !v)) throw Error("Activity plot regression; see verdict and screenshot");
