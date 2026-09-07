// One-request, FileIo-only physical subset: independent raw-to-rendered waterfall check.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn} from 'node:child_process';
const [exeArg, sourceArg, outArg, theme = 'dark', mode] = process.argv.slice(2);
if (!exeArg || !sourceArg || !outArg || !['light','dark','contrast'].includes(theme)) throw Error('Usage: <exe> <one-request.ndjson> <new-output-dir> [theme] [--oracle-only]');
const [exe, source, out] = [exeArg,sourceArg,outArg].map(p=>path.resolve(p));
const hash = p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const sourceHash = hash(source);
const parse = s=>JSON.parse(s,(_k,v,c)=>typeof v==='number' && Number.isInteger(v) && !Number.isSafeInteger(v)?c.source:v);
const events = fs.readFileSync(source,'utf8').trim().split(/\r?\n/).map(parse).map(r=>r.event).filter(Boolean);
const issues = events.filter(e=>e.kind==='block_issue').map(e=>e.data);
const completions = events.filter(e=>e.kind==='block_complete').map(e=>e.data);
if (issues.length!==1 || completions.length!==1 || events.some(e=>e.kind==='pipeline')) throw Error('Gate requires exactly one paired request and FileIo observations only');
const issue=issues[0],complete=completions[0],insert=events.find(e=>e.kind==='block_insert')?.data;
if(String(issue.request_id)!==String(complete.request_id))throw Error('Unpaired request');
const origin=insert?.ts_ns??issue.ts_ns;
const expected=[];
for(const e of events.filter(e=>e.kind==='file_io')) {
 const f=e.data;
 if(f.operation!==issue.operation || f.pid!==issue.pid || f.tid!==issue.tid || f.start_ts_ns>complete.ts_ns || f.end_ts_ns<origin)continue;
 expected.push({name:f.operation[0].toUpperCase()+f.operation.slice(1)+' fd '+f.fd,layer:'syscall',x_ms:[(f.start_ts_ns-origin)/1e6,(f.end_ts_ns-origin)/1e6],duration_ns:f.end_ts_ns-f.start_ts_ns,operation:f.operation,bytes:f.requested_bytes,pid:f.pid,tid:f.tid});
}
if(insert)expected.push({name:'block queue',layer:'block_queue',x_ms:[0,(issue.ts_ns-origin)/1e6],duration_ns:issue.ts_ns-origin,operation:issue.operation,bytes:issue.bytes,pid:issue.pid,tid:issue.tid});
expected.push({name:'block device',layer:'block_device',x_ms:[(issue.ts_ns-origin)/1e6,(complete.ts_ns-origin)/1e6],duration_ns:complete.ts_ns-issue.ts_ns,operation:issue.operation,bytes:issue.bytes,pid:issue.pid,tid:issue.tid});
fs.mkdirSync(out);
fs.writeFileSync(path.join(out,'oracle.json'),JSON.stringify({source,source_sha256:sourceHash,request_key:[String(issue.request_id),String(issue.ts_ns),String(issue.device_major),String(issue.device_minor)],origin_ns:origin,expected},null,2));
if(mode==='--oracle-only'){console.log('Oracle prepared; native renderer NOT executed');process.exit(0);}
const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.startsWith('ANDROID_EBPF_QA_')));
Object.assign(env,{ANDROID_EBPF_QA_SESSION:source,ANDROID_EBPF_QA_OUTPUT:path.join(out,'result.png'),ANDROID_EBPF_QA_PAGE:'explore',ANDROID_EBPF_QA_PRESET:'4',ANDROID_EBPF_QA_THEME:theme,ANDROID_EBPF_QA_GESTURE:'table-keyboard',ANDROID_EBPF_QA_TABLE_KEYBOARD:'1',ANDROID_EBPF_QA_DEPTH:'1',ANDROID_EBPF_QA_SCALE:'1'});
const child=spawn(exe,[],{env,windowsHide:true,stdio:['ignore','pipe','pipe']});let log='';child.stdout.on('data',d=>log+=d);child.stderr.on('data',d=>log+=d);const timer=setTimeout(()=>child.kill(),45000);
const status=await new Promise((resolve,reject)=>{child.once('error',reject);child.once('exit',(code,signal)=>resolve({code,signal}));}).finally(()=>clearTimeout(timer));
fs.writeFileSync(path.join(out,'process.log'),log);
let report;try{report=parse(fs.readFileSync(path.join(out,'result.json'),'utf8'));}catch{}
const actual=report?.rendered_waterfall??[];
const matches=expected.map(e=>({expected:e,actual:actual.find(a=>a.name===e.name&&a.layer===e.layer)}));
const checks={normal_exit:status.code===0&&status.signal===null,complete:report?.phase==='Complete'&&report?.page==='Investigate'&&report?.qa_input_step===7&&!report?.qa_timed_out,source_preserved:hash(source)===sourceHash,request:JSON.stringify(report?.opened_io?.map(String))===JSON.stringify([String(issue.request_id),String(issue.ts_ns),String(issue.device_major),String(issue.device_minor)]),count:actual.length===expected.length,raw_to_plot:matches.every(({expected:e,actual:a})=>a&&a.x_ms.every((v,i)=>Math.abs(v-e.x_ms[i])<1e-9)&&a.duration_ns===e.duration_ns&&a.operation===e.operation&&a.bytes===e.bytes&&a.pid===e.pid&&a.tid===e.tid),full_bar_width:matches.every(({expected:e,actual:a})=>a&&Math.abs((a.x_ms[1]-a.x_ms[0])*1e6-e.duration_ns)<0.001),screenshot:fs.existsSync(path.join(out,'result.png'))};
fs.writeFileSync(path.join(out,'verdict.json'),JSON.stringify({checks,status,source_sha256:sourceHash,exe_sha256:hash(exe),theme,matches,visual_review:'pending'},null,2));
console.log(JSON.stringify(checks));if(Object.values(checks).some(v=>!v))process.exitCode=1;
