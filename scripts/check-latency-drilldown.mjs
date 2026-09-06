// Native histogram -> shared filter -> exact selection regression on a saved
// bounded session. Raw request timing is independently reconstructed for checks.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
const [exeArg, sourceArg, outArg, gesture = "latency-bar", theme = "dark", scale = "1"] = process.argv.slice(2);
if (!exeArg || !sourceArg || !outArg || !["latency-bar","latency-area","latency-keyboard"].includes(gesture)) {
  throw Error("Usage: node check-latency-drilldown.mjs <exe> <saved-session> <new-output-dir> [latency-bar|latency-area|latency-keyboard] [light|dark|contrast] [scale]");
}
if (!["light","dark","contrast"].includes(theme) || !Number.isFinite(+scale) || +scale < 0.5 || +scale > 3) throw Error("Invalid theme/scale");
const [exe, source, out] = [exeArg, sourceArg, outArg].map(p => path.resolve(p));
const hash = p => crypto.createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const original = hash(source);
const parseExact = text => JSON.parse(text, (key, value, context) =>
  typeof value === "number" && /^-?\d+$/.test(context?.source ?? "") ? BigInt(context.source) : value);
const pending = new Map(), inserts = new Map(), ios = [];
const id = d => [d.request_id,d.device_major,d.device_minor].join(":");
for (const line of fs.readFileSync(source,"utf8").trim().split(/\r?\n/)) {
  const r=parseExact(line), e=r.event, d=e?.data;
  if (!d) continue;
  if (e.kind === "block_insert") inserts.set(id(d), d.ts_ns);
  if (e.kind === "block_issue") pending.set(id(d), d);
  if (e.kind === "block_complete") {
    const issue=pending.get(id(d));
    if (issue) {
      ios.push({key:[issue.request_id,issue.ts_ns,issue.device_major,issue.device_minor],latency:d.ts_ns-(inserts.get(id(d))??issue.ts_ns)});
      pending.delete(id(d));inserts.delete(id(d));
    }
  }
  if (e.kind === "observed_block_completion") ios.push({key:[d.issue.request_id,d.issue.ts_ns,d.issue.device_major,d.issue.device_minor],latency:d.total_latency_ns});
}
if (!ios.length || ios.length>100000) throw Error("Use a nonempty saved detail fixture of at most 100000 completions");
if (ios.some(io=>io.key.some(v=>typeof v!=="bigint") || io.latency!==null&&typeof io.latency!=="bigint")) throw Error("Exact integer parsing requires Node.js 24 or later");
fs.mkdirSync(out);
const env=Object.fromEntries(Object.entries(process.env).filter(([key])=>!key.startsWith("ANDROID_EBPF_QA_")));
Object.assign(env,{ANDROID_EBPF_QA_OUTPUT:path.join(out,"result.png"),ANDROID_EBPF_QA_SESSION:source,ANDROID_EBPF_QA_PAGE:"overview",ANDROID_EBPF_QA_GESTURE:gesture,ANDROID_EBPF_QA_THEME:theme,ANDROID_EBPF_QA_SCALE:scale});
const child=spawn(exe,[],{env,windowsHide:true,stdio:["ignore","pipe","pipe"]});
let log="";child.stdout.on("data",d=>log+=d);child.stderr.on("data",d=>log+=d);
const timer=setTimeout(()=>child.kill(),30000);
const status=await new Promise((resolve,reject)=>{child.on("error",reject);child.on("exit",(code,signal)=>resolve({code,signal}));}).finally(()=>clearTimeout(timer));
fs.writeFileSync(path.join(out,"process.log"),log);
const reportText=fs.readFileSync(path.join(out,"result.json"),"utf8");
const report=JSON.parse(reportText), exactReport=parseExact(reportText);
const range=report.active_filter.latency_range;
const exactRange=exactReport.active_filter.latency_range;
const expected=ios.filter(io=>io.latency!==null&&exactRange&&io.latency>=exactRange.min_ns&&(exactRange.max_exclusive_ns===null||io.latency<exactRange.max_exclusive_ns)).map(io=>JSON.stringify(io.key.map(String))).sort();
const actual=(exactReport.latency_selected_keys??[]).map(k=>JSON.stringify(k.map(String))).sort();
const checks={
  process:status.code===0&&status.signal===null,
  transition:report.qa_input_step===7&&!report.qa_timed_out&&report.page==="Explore",
  exact_requests:expected.length>0&&JSON.stringify(actual)===JSON.stringify(expected),
  matching_scope:report.selection_count===expected.length&&report.completed_requests===expected.length,
  performance:Number.isFinite(report.latency_drilldown_ms)&&report.latency_drilldown_ms<5000,
  source_preserved:hash(source)===original,
  screenshot:fs.statSync(path.join(out,"result.png")).size>0,
};
fs.writeFileSync(path.join(out,"verdict.json"),JSON.stringify({checks,gesture,theme,scale,status,range,count:expected.length,drilldown_ms:report.latency_drilldown_ms,source_sha256:original,exe_sha256:hash(exe)},null,2));
console.log(JSON.stringify(checks));
if (Object.values(checks).some(v=>!v)) throw Error("Latency drilldown failed; see verdict and screenshot");
