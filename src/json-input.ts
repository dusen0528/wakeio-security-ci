import { constants } from 'node:fs';
import { open } from 'node:fs/promises';

/** Read a user-selected JSON data file without following a link or executing it. */
export async function readJsonInput(path: string, maxBytes = 16 * 1024 * 1024): Promise<unknown> {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readJsonInputBytes(path, maxBytes)));
}

/** Return the exact bounded bytes when a caller must bind metadata to the parsed input. */
export async function readJsonInputBytes(path: string, maxBytes: number): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw Object.assign(new Error('JSON input must be a regular file'), { code: 'unsafe_path' });
    if (before.size > maxBytes) throw Object.assign(new Error('JSON input exceeds byte limit'), { code: 'input_limit' });
    const buffer = Buffer.alloc(Math.min(before.size + 1, maxBytes + 1));
    let length = 0;
    while (length < buffer.length) {
      const result = await handle.read(buffer, length, buffer.length - length, length);
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    const after = await handle.stat();
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new Error('JSON input changed while reading');
    }
    return buffer.subarray(0, length);
  } finally {
    await handle.close();
  }
}
