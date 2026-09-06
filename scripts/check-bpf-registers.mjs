// Reject unsupported stack-argument ABI instructions before shipping to Android.
// Run: node scripts/check-bpf-registers.mjs path/to/android-storage-ebpf.o
import { readFileSync } from 'node:fs';

const data = readFileSync(process.argv[2]);
if (data.subarray(0, 4).toString('hex') !== '7f454c46' || data[4] !== 2 || data[5] !== 1 || data.readUInt16LE(18) !== 247) {
  throw new Error('Expected a little-endian ELF64 BPF object');
}
const sectionOffset = Number(data.readBigUInt64LE(40));
const sectionSize = data.readUInt16LE(58);
const sectionCount = data.readUInt16LE(60);
const namesHeader = sectionOffset + data.readUInt16LE(62) * sectionSize;
const namesOffset = Number(data.readBigUInt64LE(namesHeader + 24));
let checked = 0;
const failures = [];
for (let section = 0; section < sectionCount; section++) {
  const header = sectionOffset + section * sectionSize;
  if (!(data.readBigUInt64LE(header + 8) & 4n)) continue;
  const nameStart = namesOffset + data.readUInt32LE(header);
  const name = data.toString('utf8', nameStart, data.indexOf(0, nameStart));
  const offset = Number(data.readBigUInt64LE(header + 24));
  const size = Number(data.readBigUInt64LE(header + 32));
  for (let i = 0; i < size; i += 8) {
    const opcode = data[offset + i];
    const registers = data[offset + i + 1];
    if ((registers & 15) > 10 || (registers >> 4) > 10) failures.push(`${name}+${i}: register byte 0x${registers.toString(16)}`);
    checked++;
    // The second slot of LDDW is immediate data, not an instruction.
    if (opcode === 0x18) i += 8;
  }
}
if (!checked) throw new Error('No executable BPF instructions found');
if (failures.length) throw new Error(`Unsupported BPF registers (${failures.length}):\n${failures.slice(0, 20).join('\n')}`);
console.log(`PASS: ${checked} BPF instructions use only R0-R10`);
