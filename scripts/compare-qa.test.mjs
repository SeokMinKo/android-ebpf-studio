import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {rectangleOracle} from './compare-rectangle-oracle.mjs';
const event=(kind,ts)=>({event:{kind,data:{ts_ns:ts,request_id:'18446744073709551610',device_major:8,device_minor:0,sector:100,bytes:4096,operation:'read'}}});
function audit(events){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'rectangle-oracle-'));const source=path.join(dir,'capture.ndjson');try{fs.writeFileSync(source,events.map(e=>JSON.stringify(e).replace('"18446744073709551610"','18446744073709551610')).join('\n'));return rectangleOracle(source,{selected:0,selected_keys:[],read_bytes:0,write_bytes:0,origin_ns:1,axes:['Time (ms)','Address (MB)']},[[0,0],[100000,1000]]).expected;}finally{fs.unlinkSync(source);fs.rmdirSync(dir);}}
test('old unmatched issue does not poison a new lifetime beyond 30 seconds',()=>{const r=audit([event('block_issue',1),event('block_issue',30000000002),event('block_complete',30000000003)]);assert.equal(r.count,1);assert.deepEqual(r.keys,['18446744073709551610:30000000002:8:0']);assert.equal(r.read_bytes,4096);});
test('expired ambiguous lifetime permits a fresh request',()=>{assert.equal(audit([event('block_issue',1),event('block_issue',2),event('block_issue',30000000003),event('block_complete',30000000004)]).count,1);});
test('collision inside the 30 second lifetime remains ambiguous',()=>{assert.equal(audit([event('block_issue',1),event('block_issue',30000000001),event('block_complete',30000000002)]).count,0);});
test('completion exactly at TTL remains valid, after TTL is discarded',()=>{assert.equal(audit([event('block_issue',1),event('block_complete',30000000001)]).count,1);assert.equal(audit([event('block_issue',1),event('block_complete',30000000002)]).count,0);});
test('compare-filter is accepted before scale validation without launching native UI',()=>{const r=spawnSync(process.execPath,[fileURLToPath(new URL('./check-compare-interaction.mjs',import.meta.url)),'exe','base','current','out','compare-filter','4'],{encoding:'utf8'});assert.match(r.stderr,/Scale must be/);});
