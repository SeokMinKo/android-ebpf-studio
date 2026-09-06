// Native regression: startup address/chunk selection must retain unsupported-clock
// observations without inventing a selection span, throughput or source origin.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";

const [exe, baseline, current, output, theme = "light"] = process.argv.slice(2);
if (!exe || !baseline || !current || !output) {
  throw new Error("Usage: node check-compare-clock.mjs <exe> <baseline.ndjson> <unsupported-or-mixed.ndjson> <new-output-dir> [light|dark|contrast]");
}
if (!["light", "dark", "contrast"].includes(theme)) throw new Error("Invalid theme");
const sources = [baseline, current].map(p => path.resolve(p));
const digest = p => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const before = sources.map(digest);
const observations = fs.readFileSync(sources[1], "utf8").trim().split(/\r?\n/)
  .map(line => JSON.parse(line)).filter(r => r.event?.kind === "observed_block_completion")
  .map(r => r.event.data);
const unplaced = observations.filter(io => io.evidence?.clock > 0).length;
if (!unplaced || observations.length > 100000) throw new Error("Use a bounded fixture with unsupported-clock completions");
const dir = path.resolve(output);
fs.mkdirSync(dir); // Refuse an existing evidence directory.
const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("ANDROID_EBPF_QA_")));
Object.assign(env, {
  ANDROID_EBPF_QA_OUTPUT: path.join(dir, "compare.png"),
  ANDROID_EBPF_QA_SESSION: sources[1],
  ANDROID_EBPF_QA_BASELINE: sources[0],
  ANDROID_EBPF_QA_PAGE: "compare",
  ANDROID_EBPF_QA_AXES: "address-chunk",
  ANDROID_EBPF_QA_THEME: theme,
  ANDROID_EBPF_QA_SCALE: "1",
});
const child = spawn(path.resolve(exe), [], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
let log = "";
child.stdout.on("data", d => log += d);
child.stderr.on("data", d => log += d);
const timer = setTimeout(() => child.kill(), 30000);
const status = await new Promise((resolve, reject) => {
  child.on("error", reject);
  child.on("exit", (code, signal) => resolve({ code, signal }));
}).finally(() => clearTimeout(timer));
fs.writeFileSync(path.join(dir, "process.log"), log);
const d = JSON.parse(fs.readFileSync(path.join(dir, "compare.json")));
const c = d.comparison_explore, s = c.current;
const bytes = op => observations.filter(io => io.issue.operation === op).reduce((n, io) => n + io.issue.bytes, 0);
const checks = {
  process: status.code === 0 && status.signal === null,
  ready: !d.qa_timed_out && d.phase === "Complete",
  count: s.selected === observations.length && s.unplaced_time_count === unplaced,
  volume: s.read_bytes === bytes("read") && s.write_bytes === bytes("write"),
  missing_time: s.span_ns === null && s.read_MiB_per_s === null && s.write_MiB_per_s === null,
  origin: unplaced !== observations.length || s.origin_ns === null,
  performance: c.ready_ms < 5000 && s.selection_wall_ms < 5000,
  source_preserved: sources.every((p, i) => digest(p) === before[i]),
  screenshot: fs.statSync(path.join(dir, "compare.png")).size > 0,
};
fs.writeFileSync(path.join(dir, "verdict.json"), JSON.stringify({ checks, status, source_sha256: before, exe_sha256: digest(exe), comparison: c }, null, 2));
if (Object.values(checks).some(v => !v)) throw new Error(JSON.stringify(checks));
console.log(JSON.stringify(checks));
