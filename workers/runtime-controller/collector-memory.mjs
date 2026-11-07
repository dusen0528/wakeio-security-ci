import { readFileSync } from 'node:fs';

const limit = Number(readFileSync('/sys/fs/cgroup/memory.max', 'utf8').trim());
if (limit !== 2147483648) throw new TypeError('memory_probe_limit');
process.stdout.write(JSON.stringify({ memoryMax: limit }) + '\n');
const pages = [];
for (let bytes = 0; bytes <= limit + 64 * 1024 * 1024; bytes += 8 * 1024 * 1024) {
  pages.push(Buffer.alloc(8 * 1024 * 1024, 1));
}
throw new Error('memory_limit_not_enforced');
