// Native queue-depth view check against a bounded, independently decoded source.
// Input fixtures must have no ambiguous/reused pending IDs or expired requests.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
const [exeArg, sourceArg, outArg, page = "explore", theme = "light", filter = "all", action = "view"] = process.argv.slice(2);
if (!["view", "point"].includes(action) || action === "point" && page === "overview") throw Error("Optional final action: view or point (Explore/Compare only)");
if (!exeArg || !sourceArg || !outArg || !["explore", "overview", "compare"].includes(page) || !["light", "dark", "contrast"].includes(theme) || !["all", "read"].includes(filter)) throw Error("Usage: node check-queue-depth.mjs <exe> <bounded-source> <new-output-dir> [explore|overview|compare] [light|dark|contrast] [all|read]");
if (page === "compare" && filter !== "all") throw Error("Compare has separate filters; use the dedicated comparison interaction gate");
const [exe, source, out] = [exeArg, sourceArg, outArg].map(p => path.resolve(p));
const hash = p => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const original = hash(source);
const parse = text => JSON.parse(text, (key, value, context) => typeof value === "number" && /^-?\d+$/.test(context?.source ?? "") ? BigInt(context.source) : value);
const id = d => [d.request_id, d.device_major, d.device_minor].join(":");
const pending = new Map(), inserts = new Map(), ios = [];
for (const line of fs.readFileSync(source, "utf8").trim().split(/\r?\n/)) {
  const e = parse(line).event, d = e?.data;
  if (!d) continue;
  if (e.kind === "block_insert") inserts.set(id(d), d.ts_ns);
  if (e.kind === "block_issue") {
    if (pending.has(id(d))) throw Error("Ambiguous issue; use a nonambiguous queue fixture");
    pending.set(id(d), {issue: d, at_issue: pending.size + 1});
  }
  if (e.kind === "block_complete") {
    const p = pending.get(id(d));
    if (!p) throw Error("Unmatched completion; use a paired queue fixture");
    pending.delete(id(d));
    if (d.ts_ns < p.issue.ts_ns || d.ts_ns - p.issue.ts_ns > 30000000000n) throw Error("Unordered/expired fixture; use the correlation acceptance gate");
    ios.push({key: [p.issue.request_id, p.issue.ts_ns, p.issue.device_major, p.issue.device_minor], at_issue: p.at_issue, after_completion: pending.size, operation: p.issue.operation, latency: Number(d.ts_ns - (inserts.get(id(d)) ?? p.issue.ts_ns)) / 1e6});
    inserts.delete(id(d));
  }
  if (e.kind === "observed_block_completion") ios.push({key: [d.issue.request_id, d.issue.ts_ns, d.issue.device_major, d.issue.device_minor], at_issue: d.queue_depth_at_issue == null ? null : Number(d.queue_depth_at_issue), after_completion: d.queue_depth_after == null ? null : Number(d.queue_depth_after), operation: d.issue.operation, latency: d.total_latency_ns == null ? null : Number(d.total_latency_ns) / 1e6});
}
if (!ios.length || ios.length > 12000 || ios.some(io => io.key.some(v => typeof v !== "bigint"))) throw Error("Use 1–12000 I/O and Node.js 24+; large-render performance has a separate gate");
const selected = ios.filter(io => filter === "all" || io.operation === "read");
const comparable = row => JSON.stringify({key: row.key.map(String), at_issue: row.at_issue == null ? null : Number(row.at_issue), after_completion: row.after_completion == null ? null : Number(row.after_completion)});
const expected = selected.map(comparable).sort();
const points = selected.filter(io => io.at_issue !== null && io.latency !== null).map(io => [io.at_issue, io.latency]);
const normalizePoints = values => (values ?? []).map(p => p.map(v => Number(v).toFixed(8)).join(":")).sort();
fs.mkdirSync(out);
const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("ANDROID_EBPF_QA_")));
Object.assign(env, {ANDROID_EBPF_QA_OUTPUT: path.join(out, "result.png"), ANDROID_EBPF_QA_SESSION: source, ANDROID_EBPF_QA_PAGE: page, ANDROID_EBPF_QA_THEME: theme, ANDROID_EBPF_QA_SCALE: "1", ANDROID_EBPF_QA_PRESET: "2", ANDROID_EBPF_QA_DEPTH: "1"});
if (filter === "read") env.ANDROID_EBPF_QA_FILTER = "read";
if (page === "compare") env.ANDROID_EBPF_QA_BASELINE = source;
if (action === "point") env.ANDROID_EBPF_QA_GESTURE = page === "compare" ? "compare-point" : "point";
const child = spawn(exe, [], {env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"]});
let log = ""; child.stdout.on("data", d => log += d); child.stderr.on("data", d => log += d);
const timer = setTimeout(() => child.kill(), 30000);
const status = await new Promise((resolve, reject) => {child.on("error", reject); child.on("exit", (code, signal) => resolve({code, signal}));}).finally(() => clearTimeout(timer));
fs.writeFileSync(path.join(out, "process.log"), log);
const text = fs.readFileSync(path.join(out, "result.json"), "utf8"), report = JSON.parse(text), exact = parse(text);
const samplesMatch = rows => JSON.stringify((rows ?? []).map(comparable).sort()) === JSON.stringify(expected);
const coordsMatch = coords => JSON.stringify(normalizePoints(coords)) === JSON.stringify(normalizePoints(points));
const known = selected.filter(io => io.at_issue !== null), peak = known.length ? Math.max(...known.map(io => io.at_issue)) : null;
const checks = {process: status.code === 0 && status.signal === null, complete: report.phase === "Complete" && !report.qa_timed_out, source_preserved: hash(source) === original, screenshot: fs.statSync(path.join(out, "result.png")).size > 0};
if (action === "point") {
  const keys = page === "compare" ? exact.comparison_explore.baseline?.selected_keys : exact.depth_selected_keys;
  const valid = new Set(selected.filter(io => io.at_issue !== null && io.latency !== null).map(io => JSON.stringify(io.key.map(String))));
  checks.point_summary = report.qa_input_step === 7 && keys?.length === 1 && valid.has(JSON.stringify(keys[0].map(String)));
  if (page === "compare") checks.selection_isolation = report.comparison_explore.current.selected === selected.length;
}
if (page === "compare") {
  for (const side of ["baseline", "current"]) {
    const c = report.comparison_explore[side];
    checks[side + "_samples"] = samplesMatch(exact.comparison_explore[side]?.queue_depth_samples);
    checks[side + "_graph"] = coordsMatch(c?.explorer_coordinates) && c.axes[0] === "In-flight at issue" && c.filtered === selected.length;
  }
  checks.ready_budget = report.comparison_explore.ready_ms < 5000;
} else {
  checks.samples = samplesMatch(exact.queue_depth_samples) && report.completed_requests === selected.length;
  if (page === "overview") checks.peak_and_measured_count = report.displayed_summary?.max_queue_depth === peak && report.displayed_summary?.measured_queue_depth_ios === known.length;
  else checks.graph = coordsMatch(report.explorer_coordinates) && report.explorer_axes[0] === "In-flight at issue";
}
fs.writeFileSync(path.join(out, "verdict.json"), JSON.stringify({checks, page, theme, filter, action, status, expected_count: selected.length, measured: known.length, peak, plottable: points.length, source_sha256: original, exe_sha256: hash(exe)}, null, 2));
console.log(JSON.stringify(checks));
if (Object.values(checks).some(v => !v)) throw Error("Queue-depth gate failed; inspect verdict and screenshot");
