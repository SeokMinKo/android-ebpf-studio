// Usage: node scripts/validate-file-capture.mjs capture.ndjson /device/path/final-A.bin /device/path/final-B.bin
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const [capture, ...paths] = process.argv.slice(2);
assert.equal(paths.length, 2, 'Supply the two workload file paths');
const records = readFileSync(capture, 'utf8').split('\n').filter(line => line.trim()).map(line =>
  JSON.parse(line, (key, value, context) => ['request_id', 'origin_id'].includes(key) && typeof value === 'number' ? context.source : value));
const events = records.filter(record => record.record === 'event').map(record => record.event);
assert.equal(records.find(record => record.record === 'capabilities')?.capabilities.exact_file_attribution, true);
for (const path of paths) {
  const reads = events.filter(event => event.kind === 'file_io' && event.data.path === path && event.data.operation === 'read' && event.data.io_mode === 'direct');
  assert.equal(reads.length, 64, `${path}: direct read calls`);
  assert.equal(reads.reduce((sum, event) => sum + event.data.completed_bytes, 0), 4194304, `${path}: syscall bytes`);
  assert.equal(new Set(reads.map(event => event.data.file_identity.inode)).size, 1);
  const inode = reads[0].data.file_identity.inode;
  const origins = events.filter(event => event.kind === 'request_origin' && event.data.file.inode === inode && event.data.operation === 'read');
  assert.equal(origins.length, 64, `${path}: block origins`);
  const ids = new Set(origins.map(event => event.data.request_id));
  const issues = events.filter(event => event.kind === 'block_issue' && ids.has(event.data.request_id));
  const completed = events.filter(event => event.kind === 'block_complete' && ids.has(event.data.request_id));
  assert.equal(issues.length, 64, `${path}: block issues`);
  assert.equal(new Set(completed.map(event => event.data.request_id)).size, 64, `${path}: completed requests`);
  assert.equal(issues.reduce((sum, event) => sum + event.data.bytes, 0), 4194304, `${path}: block bytes`);
  for (const origin of origins) assert.equal(origin.data.path?.path, path, `${path}: wrong origin path`);
  assert.equal(events.filter(event => event.kind === 'file_io' && event.data.file_identity?.inode === inode && event.data.path && event.data.path !== path).length, 0);
  console.log(`PASS ${path}: inode=${inode}, 64 direct reads, 64 block issues/completions, 4194304 bytes, no wrong paths`);
}
for (const health of records.filter(record => record.record === 'health')) {
  assert.equal(health.kernel_drops, 0);
  assert.equal(health.userspace_drops, 0);
}
