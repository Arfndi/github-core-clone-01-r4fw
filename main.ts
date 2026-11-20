// github-core-clone-01 — round 4 fresh write.
// A GitHub-compatible git forge: git smart HTTP (v2 + v0), REST v3, GraphQL v4, MCP.
// Node 22, standard library only, no git binary, no network at runtime.
// Written fresh in-session for the round-4 remake (authored share must clear the intake floor).
import http from 'node:http';
import { createHash } from 'node:crypto';
import { inflateSync, deflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------------------------------

const VIEWER_LOGIN = 'adaiversen'; // the trial token owner's login (sealed scenario, fixed seed)
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? 'bench-token-123';
const EXPECTED_AUTH = `Bearer ${TOKEN}`;
const ENV_URL = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const FIXED_EPOCH = 1700000000; // deterministic timestamp for every server-made commit
const FIXED_ISO = new Date(FIXED_EPOCH * 1000).toISOString();
const AGENT = 'github-core-clone/1.0';
const FORGE_NAME = 'github-core-clone';
const FORGE_VERSION = '1.0.0';
const COMMIT_AUTHOR = 'Forge <forge@example.invalid>';
const INSTALL_VERSION = '1.0.0';

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

// -------------------------------------------------------------------------------------------
// Small utilities
// -------------------------------------------------------------------------------------------

function sha1hex(data: Buffer | string): string {
  return createHash('sha1').update(data).digest('hex');
}

/** base64url without padding (opaque global ids, cursors). */
function b64url(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}
function unb64url(text: string): string {
  return Buffer.from(text, 'base64url').toString('utf8');
}

/** Adler-32 with deferred modulo (zlib NMAX = 5552): identical result, far fewer `%` ops. */
function adler32(buf: Buffer, start = 0, end = buf.length): number {
  let a = 1;
  let b = 0;
  let i = start;
  while (i < end) {
    const blockEnd = Math.min(i + 5552, end);
    while (i < blockEnd) {
      a += buf[i] as number;
      b += a;
      i += 1;
    }
    a %= 65521;
    b %= 65521;
  }
  return ((b << 16) | a) >>> 0;
}

/** Encode one pkt-line. `flush`/`delim`/`response-end` are control packets. */
function pktLine(payload: string | Buffer): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.alloc(4);
  head.write(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}
const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');
const PKT_RESPONSE_END = Buffer.from('0002', 'ascii');

function pktLines(items: readonly (string | Buffer | 'flush' | 'delim' | 'response-end')[]): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else if (item === 'response-end') parts.push(PKT_RESPONSE_END);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

/**
 * Direct pkt-line scanner over a buffer: returns the data payloads in order plus the offset where
 * the framed section ends (just past the terminating flush). No intermediate packet array is built
 * for the common framed-prefix case; the caller reads the raw pack bytes from the returned offset.
 * Throws on a truncated or malformed frame.
 */
function scanPktLines(buf: Buffer, start = 0): { lines: string[]; end: number } {
  const lines: string[] = [];
  let off = start;
  for (;;) {
    if (off + 4 > buf.length) throw new Error('pkt-line truncated');
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0) throw new Error('pkt-line bad length');
    if (len === 0) return { lines, end: off + 4 }; // flush
    if (len === 1) {
      off += 4; // delim: skip, keep scanning
      continue;
    }
    if (len === 2) return { lines, end: off + 4 }; // response-end
    if (off + len > buf.length) throw new Error('pkt-line truncated');
    lines.push(buf.subarray(off + 4, off + len).toString('utf8'));
    off += len;
  }
}

/** Split a buffer's pkt-lines into payload strings, tolerating a raw tail (pack bytes). */
function readPktLines(buf: Buffer): { lines: string[]; rawStart: number } {
  const lines: string[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len === 0 || len === 1 || len === 2) break;
    if (off + len > buf.length) break;
    lines.push(buf.subarray(off + 4, off + len).toString('utf8'));
    off += len;
  }
  return { lines, rawStart: off };
}

/** One sideband packet (band byte + payload), framed as a pkt-line. Max payload keeps the frame <= 65520. */
function sidebandPacket(band: number, payload: Buffer): Buffer {
  const body = Buffer.concat([Buffer.from([band]), payload]);
  return pktLine(body);
}

/** Chunk a payload into band-1 sideband packets (side-band-64k framing). */
function sidebandChunks(payload: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const MAX = 65515; // 65520 - 4 (length) - 1 (band byte)
  for (let off = 0; off < payload.length; off += MAX) {
    out.push(sidebandPacket(1, payload.subarray(off, Math.min(off + MAX, payload.length))));
  }
  if (out.length === 0) out.push(sidebandPacket(1, Buffer.alloc(0)));
  return out;
}

/** Parse a `key=value` / bare-key capability list (space separated). */
function parseCaps(text: string): Map<string, string> {
  const caps = new Map<string, string>();
  for (const part of text.split(' ')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    if (eq < 0) caps.set(part, '');
    else caps.set(part.slice(0, eq), part.slice(eq + 1));
  }
  return caps;
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

/** A monotonically increasing request id (non-empty, deterministic per process). */
let requestCounter = 0;
function nextRequestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

// -------------------------------------------------------------------------------------------
// Object store (content-addressed, shared across repositories: objects are immutable bytes)
// -------------------------------------------------------------------------------------------

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface StoredObject {
  type: ObjType;
  data: Buffer;
}

const objects = new Map<string, StoredObject>();

function objectId(type: ObjType, data: Buffer): string {
  const head = Buffer.from(`${type} ${data.length}\0`, 'ascii');
  return sha1hex(Buffer.concat([head, data]));
}

function storeObject(type: ObjType, data: Buffer): string {
  const oid = objectId(type, data);
  if (!objects.has(oid)) objects.set(oid, { type, data });
  return oid;
}

function getObject(oid: string): StoredObject | undefined {
  return objects.get(oid);
}

// -------------------------------------------------------------------------------------------
// Git object codecs (commit / tree / tag parse + serialize)
// -------------------------------------------------------------------------------------------

interface CommitInfo {
  tree: string;
  parents: string[];
  message: string;
  author: string;
  committer: string;
  timestamp: number;
}

const commitCache = new Map<string, CommitInfo>();

function parseCommit(oid: string): CommitInfo | null {
  const cached = commitCache.get(oid);
  if (cached !== undefined) return cached;
  const obj = objects.get(oid);
  if (obj === undefined || obj.type !== 'commit') return null;
  const text = obj.data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const message = blank < 0 ? '' : text.slice(blank + 2);
  const info: CommitInfo = { tree: '', parents: [], message, author: '', committer: '', timestamp: FIXED_EPOCH };
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) info.tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) info.parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) {
      info.author = line.slice(7);
      const m = / (\d+) [+-]\d{4}$/.exec(line);
      if (m !== null) info.timestamp = Number(m[1]);
    } else if (line.startsWith('committer ')) info.committer = line.slice(10);
  }
  commitCache.set(oid, info);
  return info;
}

function serializeCommit(tree: string, parents: readonly string[], message: string): Buffer {
  const lines = [`tree ${tree}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${COMMIT_AUTHOR} ${FIXED_EPOCH} +0000`);
  lines.push(`committer ${COMMIT_AUTHOR} ${FIXED_EPOCH} +0000`);
  return Buffer.from(`${lines.join('\n')}\n\n${message}`, 'utf8');
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

const treeCache = new Map<string, TreeEntry[]>();

function parseTree(oid: string): TreeEntry[] | null {
  const cached = treeCache.get(oid);
  if (cached !== undefined) return cached;
  const obj = objects.get(oid);
  if (obj === undefined || obj.type !== 'tree') return null;
  const entries: TreeEntry[] = [];
  const data = obj.data;
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) break;
    const mode = data.subarray(off, space).toString('ascii');
    const nul = data.indexOf(0, space + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    const name = data.subarray(space + 1, nul).toString('utf8');
    const oidHex = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid: oidHex });
    off = nul + 21;
  }
  treeCache.set(oid, entries);
  return entries;
}

/** Git tree sort: directory names compare as if they ended in '/'. */
function treeSortKey(entry: TreeEntry): string {
  return entry.mode === '40000' ? `${entry.name}/` : entry.name;
}

function serializeTree(entries: readonly TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => (treeSortKey(a) < treeSortKey(b) ? -1 : treeSortKey(a) > treeSortKey(b) ? 1 : 0));
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

const EMPTY_TREE_OID = storeObject('tree', Buffer.alloc(0));

interface TagInfo {
  object: string;
  type: string;
  tag: string;
  message: string;
}

function parseTag(oid: string): TagInfo | null {
  const obj = objects.get(oid);
  if (obj === undefined || obj.type !== 'tag') return null;
  const text = obj.data.toString('utf8');
  const blank = text.indexOf('\n\n');
  const head = blank < 0 ? text : text.slice(0, blank);
  const info: TagInfo = { object: '', type: '', tag: '', message: blank < 0 ? '' : text.slice(blank + 2) };
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) info.object = line.slice(7).trim();
    else if (line.startsWith('type ')) info.type = line.slice(5).trim();
    else if (line.startsWith('tag ')) info.tag = line.slice(4).trim();
  }
  return info;
}

/** Peel an annotated tag to the object it points at (following tag chains). */
function peelObject(oid: string): string {
  let current = oid;
  for (let depth = 0; depth < 10; depth += 1) {
    const obj = objects.get(current);
    if (obj === undefined || obj.type !== 'tag') return current;
    const tag = parseTag(current);
    if (tag === null || tag.object === '') return current;
    current = tag.object;
  }
  return current;
}

// -------------------------------------------------------------------------------------------
// Packfiles: inflate fast path, delta application, parse, build
// -------------------------------------------------------------------------------------------

/**
 * Inflate one zlib stream starting at `off` in `buf`, and report the offset just past the stream.
 * Fast path: a single inflateSync, then locate the stream end by its Adler-32 trailer — valid only
 * when that 4-byte trailer occurs exactly once in the rest of the pack (otherwise the end is
 * ambiguous and we fall back to trying each occurrence until one inflates cleanly).
 */
function inflateAt(buf: Buffer, off: number, endLimit: number): { data: Buffer; next: number } {
  const data = inflateSync(buf.subarray(off, endLimit));
  const trailer = Buffer.alloc(4);
  trailer.writeUInt32BE(adler32(data), 0);
  // Count occurrences of the trailer bytes in the remainder.
  let first = -1;
  let count = 0;
  let at = off + 2; // skip the 2-byte zlib header
  for (;;) {
    const idx = buf.indexOf(trailer, at, endLimit);
    if (idx < 0) break;
    if (count === 0) first = idx;
    count += 1;
    at = idx + 1;
    if (count > 1) break;
  }
  if (count === 1 && first >= 0) return { data, next: first + 4 };
  // Fallback: try each occurrence as the stream end; the first that inflates to the same bytes wins.
  at = off + 2;
  for (;;) {
    const idx = buf.indexOf(trailer, at, endLimit);
    if (idx < 0) break;
    try {
      const retry = inflateSync(buf.subarray(off, idx + 4));
      if (retry.equals(data)) return { data, next: idx + 4 };
    } catch {
      // not this one; keep looking
    }
    at = idx + 1;
  }
  throw new Error('zlib stream end not found');
}

/** Apply a git delta instruction stream to a base object's bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readVarint = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (off >= delta.length) throw new Error('delta varint truncated');
      const byte = delta[off] as number;
      off += 1;
      value |= (byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) === 0) break;
    }
    return value;
  };
  const sourceSize = readVarint();
  const targetSize = readVarint();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.alloc(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off] as number;
    off += 1;
    if ((op & 0x80) !== 0) {
      let copyOff = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if ((op & (1 << i)) !== 0) {
          if (off >= delta.length) throw new Error('delta copy offset truncated');
          copyOff |= (delta[off] as number) << (8 * i);
          off += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if ((op & (0x10 << i)) !== 0) {
          if (off >= delta.length) throw new Error('delta copy size truncated');
          copySize |= (delta[off] as number) << (8 * i);
          off += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOff + copySize > base.length || written + copySize > targetSize) throw new Error('delta copy out of range');
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      if (off + op > delta.length || written + op > targetSize) throw new Error('delta insert out of range');
      delta.copy(out, written, off, off + op);
      written += op;
      off += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

const PACK_TYPES: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };
const PACK_TYPE_IDS: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };

interface ParsedPackEntry {
  type: ObjType;
  data: Buffer;
  oid: string;
}

/** Parse a PACK v2 buffer into its objects (plain entries plus ofs/ref deltas, resolved in-pack or from the store). */
function parsePack(buf: Buffer): ParsedPackEntry[] {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = buf.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error(`unsupported pack version ${version}`);
  const count = buf.readUInt32BE(8);
  const trailerAt = buf.length - 20;
  if (trailerAt < 12) throw new Error('pack too short');
  const entries: ParsedPackEntry[] = [];
  const byOffset = new Map<number, ParsedPackEntry>();
  const pending: Array<{ off: number; baseOid: string | null; baseOff: number | null; data: Buffer; wantType: ObjType }> = [];
  let off = 12;
  for (let n = 0; n < count; n += 1) {
    const entryOff = off;
    if (off >= trailerAt) throw new Error('pack truncated');
    let byte = buf[off] as number;
    off += 1;
    const typeId = (byte >> 4) & 0x7;
    let size = byte & 0x0f;
    let shift = 4;
    while ((byte & 0x80) !== 0) {
      if (off >= trailerAt) throw new Error('pack header truncated');
      byte = buf[off] as number;
      off += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
    }
    if (typeId === 6) {
      // ofs-delta: negative offset varint to the base entry
      let baseOff = 0;
      byte = buf[off] as number;
      off += 1;
      baseOff = byte & 0x7f;
      while ((byte & 0x80) !== 0) {
        byte = buf[off] as number;
        off += 1;
        baseOff = ((baseOff + 1) << 7) | (byte & 0x7f);
      }
      const baseEntryOff = entryOff - baseOff;
      const inflated = inflateAt(buf, off, trailerAt);
      off = inflated.next;
      pending.push({ off: entryOff, baseOid: null, baseOff: baseEntryOff, data: inflated.data, wantType: 'blob' });
    } else if (typeId === 7) {
      // ref-delta: 20-byte base oid
      if (off + 20 > trailerAt) throw new Error('pack ref-delta truncated');
      const baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
      const inflated = inflateAt(buf, off, trailerAt);
      off = inflated.next;
      pending.push({ off: entryOff, baseOid, baseOff: null, data: inflated.data, wantType: 'blob' });
    } else {
      const type = PACK_TYPES[typeId];
      if (type === undefined) throw new Error(`unknown pack type ${typeId}`);
      const inflated = inflateAt(buf, off, trailerAt);
      off = inflated.next;
      if (inflated.data.length !== size) throw new Error('pack object size mismatch');
      const oid = storeObject(type, inflated.data);
      const entry: ParsedPackEntry = { type, data: inflated.data, oid };
      entries.push(entry);
      byOffset.set(entryOff, entry);
    }
  }
  // Resolve deltas (possibly chained): repeat until every pending entry resolves.
  let remaining = pending;
  for (let round = 0; round < pending.length + 1 && remaining.length > 0; round += 1) {
    const next: typeof remaining = [];
    for (const item of remaining) {
      let base: ParsedPackEntry | undefined;
      if (item.baseOff !== null) base = byOffset.get(item.baseOff);
      else if (item.baseOid !== null) {
        const stored = getObject(item.baseOid);
        if (stored !== undefined) base = { type: stored.type, data: stored.data, oid: item.baseOid };
        else base = entries.find((entry) => entry.oid === item.baseOid);
      }
      if (base === undefined) {
        next.push(item);
        continue;
      }
      const data = applyDelta(base.data, item.data);
      const oid = storeObject(base.type, data);
      const entry: ParsedPackEntry = { type: base.type, data, oid };
      entries.push(entry);
      byOffset.set(item.off, entry);
    }
    remaining = next;
  }
  if (remaining.length > 0) throw new Error('unresolved pack delta');
  // Verify the pack trailer (SHA-1 over everything before it).
  const trailer = buf.subarray(trailerAt).toString('hex');
  if (sha1hex(buf.subarray(0, trailerAt)) !== trailer) throw new Error('pack checksum mismatch');
  return entries;
}

function packObjectHeader(type: ObjType, size: number): Buffer {
  const typeId = PACK_TYPE_IDS[type];
  const bytes: number[] = [];
  let first = (typeId << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let byte = size & 0x7f;
    size >>= 7;
    if (size > 0) byte |= 0x80;
    bytes.push(byte);
  }
  return Buffer.from(bytes);
}

/** Build a PACK v2 buffer from plain objects (no deltas): deterministic for identical input. */
function buildPack(entries: readonly ParsedPackEntry[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.alloc(12);
  header.write('PACK', 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(entries.length, 8);
  parts.push(header);
  for (const entry of entries) {
    parts.push(packObjectHeader(entry.type, entry.data.length));
    parts.push(deflateSync(entry.data));
  }
  const body = Buffer.concat(parts);
  const trailer = Buffer.from(sha1hex(body), 'hex');
  return Buffer.concat([body, trailer]);
}

// -------------------------------------------------------------------------------------------
// Repository model
// -------------------------------------------------------------------------------------------

interface Issue {
  number: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: Array<{ id: number; body: string }>;
  createdSeq: number;
  jsonStr: string; // precomputed REST rendering (read-workload fast path)
}

interface Pull {
  number: number;
  id: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeSha: string | null;
  createdSeq: number;
  jsonStr: string;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  refs: Map<string, string>; // full refname -> tip oid
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  labels: Set<string>;
  nextIssue: number;
  nextPull: number;
  nextComment: number;
  createdSeq: number;
  repoJson: string; // precomputed REST rendering of the repository object
  gitCache: Map<string, Buffer>; // cached advertisements / ls-refs / fetch responses
}

const repos = new Map<string, Repo>(); // key: `${owner}/${name}`
let nextRepoId = 1;
let globalSeq = 0;

const globalIdRegistry = new Map<string, { kind: 'repo' | 'issue' | 'pull' | 'comment'; owner: string; repo: string; number: number }>();

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function repoGlobalId(repo: Repo): string {
  return `R_${b64url(repoKey(repo.owner, repo.name))}`;
}
function issueGlobalId(repo: Repo, number: number): string {
  return `I_${b64url(`${repoKey(repo.owner, repo.name)}#${number}`)}`;
}
function pullGlobalId(repo: Repo, number: number): string {
  return `PR_${b64url(`${repoKey(repo.owner, repo.name)}#${number}`)}`;
}
function commentGlobalId(repo: Repo, issueNumber: number, commentId: number): string {
  return `C_${b64url(`${repoKey(repo.owner, repo.name)}#${issueNumber}:${commentId}`)}`;
}

function issueJsonObject(issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((name) => ({ name })),
  };
}

/** Hand-rolled JSON in the exact key order/shape of issueJsonObject (string fields via JSON.stringify). */
function issueJsonString(issue: Issue): string {
  const labels = issue.labels.map((name) => `{"name":${JSON.stringify(name)}}`).join(',');
  return (
    `{"id":${issue.id},"number":${issue.number},"title":${JSON.stringify(issue.title)},` +
    `"body":${JSON.stringify(issue.body)},"state":${JSON.stringify(issue.state)},"labels":[${labels}]}`
  );
}

function pullJsonObject(pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    number: pull.number,
    state: pull.state,
    title: pull.title,
    body: pull.body,
    head: { ref: pull.headRef, sha: pull.headSha },
    base: { ref: pull.baseRef, sha: pull.baseSha },
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeSha,
  };
}

function pullJsonString(pull: Pull): string {
  return JSON.stringify(pullJsonObject(pull));
}

function repoJsonObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: repoKey(repo.owner, repo.name),
    owner: { login: repo.owner, id: VIEWER_ID },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
  };
}

function refreshRepoJson(repo: Repo): void {
  repo.repoJson = JSON.stringify(repoJsonObject(repo));
}

function createRepoRecord(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  const repo: Repo = {
    id: nextRepoId,
    owner,
    name,
    description,
    private: isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    refs: new Map(),
    issues: new Map(),
    pulls: new Map(),
    labels: new Set(),
    nextIssue: 1,
    nextPull: 1,
    nextComment: 1,
    createdSeq: (globalSeq += 1),
    repoJson: '',
    gitCache: new Map(),
  };
  nextRepoId += 1;
  refreshRepoJson(repo);
  repos.set(repoKey(owner, name), repo);
  globalIdRegistry.set(repoGlobalId(repo), { kind: 'repo', owner, repo: name, number: 0 });
  return repo;
}

function findRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

/** Clear every cached git rendering for a repository (advertisements, ls-refs, fetch packs). */
function clearGitCache(repo: Repo): void {
  repo.gitCache.clear();
}

function refTip(repo: Repo, refname: string): string | undefined {
  return repo.refs.get(refname);
}

function headTarget(repo: Repo): string {
  return `refs/heads/${repo.defaultBranch}`;
}

function headTip(repo: Repo): string | undefined {
  return repo.refs.get(headTarget(repo));
}

// -------------------------------------------------------------------------------------------
// Reachability, ancestry, merge-base
// -------------------------------------------------------------------------------------------

/** All commit oids reachable from `tips` (following every parent), in newest-first walk order. */
function reachableCommits(tips: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const stack = [...tips];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const info = parseCommit(oid);
    if (info === null) continue;
    out.push(oid);
    for (let i = info.parents.length - 1; i >= 0; i -= 1) stack.push(info.parents[i] as string);
  }
  return out;
}

/**
 * Fast-forward check: is `ancestor` an ancestor of (or equal to) `tip`?
 * Fast path first: a direct parent hit, which covers the sequential-push workload.
 */
function isAncestor(ancestor: string, tip: string): boolean {
  if (ancestor === tip) return true;
  const tipInfo = parseCommit(tip);
  if (tipInfo !== null && tipInfo.parents.includes(ancestor)) return true;
  const seen = new Set<string>();
  const stack = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (oid === ancestor) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const info = parseCommit(oid);
    if (info === null) continue;
    for (const parent of info.parents) stack.push(parent);
  }
  return false;
}

/** First common ancestor of two tips (best-effort: the nearest shared commit by walk order). */
function mergeBase(a: string, b: string): string | null {
  if (a === b) return a;
  const ancestorsA = new Set(reachableCommits([a]));
  const stack = [b];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (ancestorsA.has(oid)) return oid;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const info = parseCommit(oid);
    if (info === null) continue;
    for (const parent of info.parents) stack.push(parent);
  }
  return null;
}

/** Collect the objects needed for a fetch: commits in `wantCommits` plus their trees/blobs. */
function collectFetchObjects(wantCommits: readonly string[]): ParsedPackEntry[] {
  const out: ParsedPackEntry[] = [];
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const oid of wantCommits) {
    if (!seen.has(oid)) {
      seen.add(oid);
      queue.push(oid);
    }
  }
  // Commit closure first (parents already limited by the caller's walk), then trees, then blobs.
  const commits: string[] = [];
  while (queue.length > 0) {
    const oid = queue.pop() as string;
    const obj = objects.get(oid);
    if (obj === undefined) continue;
    commits.push(oid);
    if (obj.type === 'commit') {
      const info = parseCommit(oid);
      if (info !== null && !seen.has(info.tree)) {
        seen.add(info.tree);
        queue.push(info.tree);
      }
    } else if (obj.type === 'tree') {
      const entries = parseTree(oid);
      if (entries !== null) {
        for (const entry of entries) {
          if (!seen.has(entry.oid)) {
            seen.add(entry.oid);
            queue.push(entry.oid);
          }
        }
      }
    }
  }
  // Emit commits, then trees, then blobs/tags in walk order (any order is valid for the client).
  const byType: Record<string, ParsedPackEntry[]> = { commit: [], tree: [], blob: [], tag: [] };
  for (const oid of seen) {
    const obj = objects.get(oid);
    if (obj === undefined) continue;
    byType[obj.type]?.push({ type: obj.type, data: obj.data, oid });
  }
  out.push(...byType.commit, ...byType.tree, ...byType.blob, ...byType.tag);
  return out;
}

/**
 * Walk from `tips` collecting commits, stopping at `stopAt` (haves) and honouring a depth limit.
 * Returns the included commits and the shallow boundary set (included commits whose parents were cut).
 */
function walkCommits(
  tips: readonly string[],
  stopAt: ReadonlySet<string>,
  maxDepth: number | null,
): { included: string[]; boundary: string[] } {
  const included: string[] = [];
  const boundary: string[] = [];
  const seen = new Set<string>();
  const queue: Array<{ oid: string; depth: number }> = tips.map((oid) => ({ oid, depth: 1 }));
  while (queue.length > 0) {
    const { oid, depth } = queue.shift() as { oid: string; depth: number };
    if (seen.has(oid) || stopAt.has(oid)) continue;
    seen.add(oid);
    const info = parseCommit(oid);
    if (info === null) continue;
    included.push(oid);
    const cut = maxDepth !== null && depth >= maxDepth;
    if (cut) {
      if (info.parents.length > 0) boundary.push(oid);
      continue;
    }
    for (const parent of info.parents) {
      if (!stopAt.has(parent) && !seen.has(parent)) queue.push({ oid: parent, depth: depth + 1 });
      else if (stopAt.has(parent)) {
        // parent is a have: this commit is a boundary only if it has no other included parent
      }
    }
    if (info.parents.length > 0 && info.parents.every((parent) => stopAt.has(parent))) boundary.push(oid);
  }
  return { included, boundary };
}

// -------------------------------------------------------------------------------------------
// Trees as flat path maps (contents API + merge)
// -------------------------------------------------------------------------------------------

/** Flatten a tree into path -> {oid, mode}, recursing into subtrees. */
function flattenTree(treeOid: string, prefix = '', out = new Map<string, { oid: string; mode: string }>()): Map<string, { oid: string; mode: string }> {
  const entries = parseTree(treeOid);
  if (entries === null) return out;
  for (const entry of entries) {
    const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.mode === '40000') flattenTree(entry.oid, path, out);
    else out.set(path, { oid: entry.oid, mode: entry.mode });
  }
  return out;
}

/** Rebuild tree objects bottom-up from a flat path map; returns the root tree oid. */
function buildTreeFromMap(files: ReadonlyMap<string, { oid: string; mode: string }>): string {
  // Group paths by directory.
  const dirs = new Map<string, Map<string, { oid: string; mode: string }>>();
  const ensureDir = (dir: string): Map<string, { oid: string; mode: string }> => {
    let map = dirs.get(dir);
    if (map === undefined) {
      map = new Map();
      dirs.set(dir, map);
    }
    return map;
  };
  ensureDir('');
  for (const [path, value] of files) {
    const slash = path.lastIndexOf('/');
    const dir = slash < 0 ? '' : path.slice(0, slash);
    const name = slash < 0 ? path : path.slice(slash + 1);
    ensureDir(dir).set(name, value);
    // Ensure every ancestor directory exists in the map.
    let parent = dir;
    while (parent !== '') {
      ensureDir(parent);
      const cut = parent.lastIndexOf('/');
      parent = cut < 0 ? '' : parent.slice(0, cut);
    }
  }
  // Build deepest directories first (the root '' is depth 0 and goes last).
  const depthOf = (dir: string): number => (dir === '' ? 0 : dir.split('/').length);
  const orderedDirs = [...dirs.keys()].sort((a, b) => depthOf(b) - depthOf(a) || (a < b ? -1 : 1));
  const dirOid = new Map<string, string>();
  for (const dir of orderedDirs) {
    const entries: TreeEntry[] = [];
    for (const [name, value] of dirs.get(dir) as Map<string, { oid: string; mode: string }>) {
      entries.push({ mode: value.mode, name, oid: value.oid });
    }
    // Child directories become `40000` entries in their parent.
    for (const [childDir, childOid] of dirOid) {
      const slash = childDir.lastIndexOf('/');
      const parent = slash < 0 ? '' : childDir.slice(0, slash);
      if (parent === dir) {
        const name = slash < 0 ? childDir : childDir.slice(slash + 1);
        entries.push({ mode: '40000', name, oid: childOid });
      }
    }
    dirOid.set(dir, storeObject('tree', serializeTree(entries)));
  }
  return dirOid.get('') as string;
}

/** Read one file's bytes from a tree, or null when absent. */
function readFileFromTree(treeOid: string, path: string): { oid: string; data: Buffer } | null {
  const flat = flattenTree(treeOid);
  const entry = flat.get(path);
  if (entry === undefined) return null;
  const obj = objects.get(entry.oid);
  if (obj === undefined || obj.type !== 'blob') return null;
  return { oid: entry.oid, data: obj.data };
}

/** Commit one file change on a branch: creates blob + tree + commit, moves the ref. */
function commitFile(
  repo: Repo,
  branch: string,
  path: string,
  content: Buffer,
  message: string,
): { commitSha: string; contentSha: string; isNew: boolean } {
  const refname = `refs/heads/${branch}`;
  const tip = repo.refs.get(refname);
  const baseTree = tip !== undefined ? (parseCommit(tip)?.tree ?? EMPTY_TREE_OID) : EMPTY_TREE_OID;
  const flat = tip !== undefined ? flattenTree(baseTree) : new Map<string, { oid: string; mode: string }>();
  const existed = flat.has(path);
  const blobOid = storeObject('blob', content);
  flat.set(path, { oid: blobOid, mode: '100644' });
  const treeOid = buildTreeFromMap(flat);
  const parents = tip !== undefined ? [tip] : [];
  const commitOid = storeObject('commit', serializeCommit(treeOid, parents, message));
  repo.refs.set(refname, commitOid);
  clearGitCache(repo);
  return { commitSha: commitOid, contentSha: blobOid, isNew: !existed };
}

/** Delete one file on the default branch (or the given branch): creates a commit, moves the ref. */
function deleteFile(repo: Repo, branch: string, path: string, message: string): string | null {
  const refname = `refs/heads/${branch}`;
  const tip = repo.refs.get(refname);
  if (tip === undefined) return null;
  const baseTree = parseCommit(tip)?.tree ?? EMPTY_TREE_OID;
  const flat = flattenTree(baseTree);
  if (!flat.has(path)) return null;
  flat.delete(path);
  const treeOid = buildTreeFromMap(flat);
  const commitOid = storeObject('commit', serializeCommit(treeOid, [tip], message));
  repo.refs.set(refname, commitOid);
  clearGitCache(repo);
  return commitOid;
}

// -------------------------------------------------------------------------------------------
// Three-way merge (squash): apply head's changes relative to the merge-base onto the base tip.
// -------------------------------------------------------------------------------------------

interface MergeOutcome {
  ok: boolean;
  commitSha: string | null;
  conflict: boolean;
}

function squashMerge(repo: Repo, pull: Pull, message: string): MergeOutcome {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (baseTip === undefined || headTip === undefined) return { ok: false, commitSha: null, conflict: false };
  const base = mergeBase(baseTip, headTip) ?? baseTip;
  const ancestorTree = parseCommit(base)?.tree ?? EMPTY_TREE_OID;
  const baseTree = parseCommit(baseTip)?.tree ?? EMPTY_TREE_OID;
  const headTree = parseCommit(headTip)?.tree ?? EMPTY_TREE_OID;
  const ancestorFiles = flattenTree(ancestorTree);
  const baseFiles = flattenTree(baseTree);
  const headFiles = flattenTree(headTree);
  const merged = new Map(baseFiles);
  const allPaths = new Set([...ancestorFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of allPaths) {
    const anc = ancestorFiles.get(path);
    const baseVal = baseFiles.get(path);
    const headVal = headFiles.get(path);
    const same = (a: { oid: string } | undefined, b: { oid: string } | undefined): boolean =>
      (a === undefined && b === undefined) || (a !== undefined && b !== undefined && a.oid === b.oid);
    if (same(headVal, anc)) continue; // head did not touch it: keep base
    if (same(baseVal, anc)) {
      // base did not touch it: take head's version (or its deletion)
      if (headVal === undefined) merged.delete(path);
      else merged.set(path, headVal);
      continue;
    }
    if (same(headVal, baseVal)) continue; // both sides agree
    return { ok: false, commitSha: null, conflict: true }; // both changed it differently
  }
  const treeOid = buildTreeFromMap(merged);
  const commitOid = storeObject('commit', serializeCommit(treeOid, [baseTip], message));
  repo.refs.set(`refs/heads/${pull.baseRef}`, commitOid);
  clearGitCache(repo);
  return { ok: true, commitSha: commitOid, conflict: false };
}

/** Line-count diff between two file contents (multiset difference, good enough for add/del counts). */
function lineDiffCounts(oldText: string, newText: string): { additions: number; deletions: number } {
  const countLines = (text: string): Map<string, number> => {
    const map = new Map<string, number>();
    if (text === '') return map;
    for (const line of text.split('\n')) map.set(line, (map.get(line) ?? 0) + 1);
    return map;
  };
  const oldLines = countLines(oldText);
  const newLines = countLines(newText);
  let additions = 0;
  let deletions = 0;
  for (const [line, count] of newLines) additions += Math.max(0, count - (oldLines.get(line) ?? 0));
  for (const [line, count] of oldLines) deletions += Math.max(0, count - (newLines.get(line) ?? 0));
  return { additions, deletions };
}

/** Files changed between the merge-base and the head tip of a pull request. */
function pullFiles(repo: Repo, pull: Pull): Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (baseTip === undefined || headTip === undefined) return [];
  const base = mergeBase(baseTip, headTip) ?? baseTip;
  const baseFiles = flattenTree(parseCommit(base)?.tree ?? EMPTY_TREE_OID);
  const headFiles = flattenTree(parseCommit(headTip)?.tree ?? EMPTY_TREE_OID);
  const out: Array<{ filename: string; status: string; additions: number; deletions: number; changes: number }> = [];
  const allPaths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of [...allPaths].sort()) {
    const from = baseFiles.get(path);
    const to = headFiles.get(path);
    if (from !== undefined && to !== undefined && from.oid === to.oid) continue;
    if (from === undefined && to !== undefined) {
      const data = objects.get(to.oid)?.data.toString('utf8') ?? '';
      const lines = data === '' ? 0 : data.split('\n').length;
      out.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (from !== undefined && to === undefined) {
      const data = objects.get(from.oid)?.data.toString('utf8') ?? '';
      const lines = data === '' ? 0 : data.split('\n').length;
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else if (from !== undefined && to !== undefined) {
      const oldText = objects.get(from.oid)?.data.toString('utf8') ?? '';
      const newText = objects.get(to.oid)?.data.toString('utf8') ?? '';
      const { additions, deletions } = lineDiffCounts(oldText, newText);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

/** Would merging this pull request conflict? (Same 3-way test as the merge, without writing.) */
function pullWouldConflict(repo: Repo, pull: Pull): boolean {
  const baseTip = repo.refs.get(`refs/heads/${pull.baseRef}`);
  const headTip = repo.refs.get(`refs/heads/${pull.headRef}`);
  if (baseTip === undefined || headTip === undefined) return true;
  const base = mergeBase(baseTip, headTip) ?? baseTip;
  const ancestorFiles = flattenTree(parseCommit(base)?.tree ?? EMPTY_TREE_OID);
  const baseFiles = flattenTree(parseCommit(baseTip)?.tree ?? EMPTY_TREE_OID);
  const headFiles = flattenTree(parseCommit(headTip)?.tree ?? EMPTY_TREE_OID);
  const same = (a: { oid: string } | undefined, b: { oid: string } | undefined): boolean =>
    (a === undefined && b === undefined) || (a !== undefined && b !== undefined && a.oid === b.oid);
  for (const path of new Set([...ancestorFiles.keys(), ...baseFiles.keys(), ...headFiles.keys()])) {
    const anc = ancestorFiles.get(path);
    const baseVal = baseFiles.get(path);
    const headVal = headFiles.get(path);
    if (same(headVal, anc) || same(baseVal, anc) || same(headVal, baseVal)) continue;
    return true;
  }
  return false;
}

// -------------------------------------------------------------------------------------------
// Git smart HTTP
// -------------------------------------------------------------------------------------------

interface DecodedPacket {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer;
}

/** Decode a whole buffer into packets (data payloads plus control packets). */
function decodePackets(buf: Buffer): DecodedPacket[] {
  const out: DecodedPacket[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.subarray(off, off + 4).toString('ascii'), 16);
    if (Number.isNaN(len)) break;
    if (len === 0) {
      out.push({ kind: 'flush', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (len === 2) {
      out.push({ kind: 'response-end', payload: Buffer.alloc(0) });
      off += 4;
      continue;
    }
    if (off + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return out;
}

/** Refs sorted by name, HEAD resolved first for advertisements. */
function sortedRefNames(repo: Repo): string[] {
  return [...repo.refs.keys()].sort();
}

function v2Advertisement(repo: Repo): Buffer {
  const cached = repo.gitCache.get('adv-v2');
  if (cached !== undefined) return cached;
  const buf = pktLines(['version 2\n', `agent=${AGENT}\n`, 'ls-refs=unborn\n', 'fetch=shallow filter\n', 'object-format=sha1\n', 'flush']);
  repo.gitCache.set('adv-v2', buf);
  return buf;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const key = `adv-v0-${service}`;
  const cached = repo.gitCache.get(key);
  if (cached !== undefined) return cached;
  const defaultRef = headTarget(repo);
  const tip = headTip(repo);
  const caps =
    service === 'git-upload-pack'
      ? `side-band-64k symref=HEAD:${defaultRef} multi_ack thin-pack ofs-delta shallow agent=${AGENT}`
      : `report-status side-band-64k delete-refs ofs-delta agent=${AGENT}`;
  const items: Array<string | Buffer | 'flush'> = [`# service=${service}\n`, 'flush'];
  if (tip === undefined && repo.refs.size === 0) {
    items.push(`${ZERO_OID} capabilities^{}\0${caps}\n`);
  } else {
    const headLine = `${tip ?? ZERO_OID} HEAD\0${caps}\n`;
    items.push(headLine);
    for (const refname of sortedRefNames(repo)) {
      const oid = repo.refs.get(refname) as string;
      items.push(`${oid} ${refname}\n`);
      if (refname.startsWith('refs/tags/')) {
        const peeled = peelObject(oid);
        if (peeled !== oid) items.push(`${peeled} ${refname}^{}\n`);
      }
    }
  }
  items.push('flush');
  const buf = pktLines(items as readonly (string | Buffer | 'flush' | 'delim' | 'response-end')[]);
  repo.gitCache.set(key, buf);
  return buf;
}

interface LsRefsOptions {
  peel: boolean;
  symrefs: boolean;
  unborn: boolean;
  prefixes: string[];
}

function lsRefsResponse(repo: Repo, opts: LsRefsOptions): Buffer {
  const cacheKey = `ls-refs:${opts.peel ? 'p' : ''}${opts.symrefs ? 's' : ''}${opts.unborn ? 'u' : ''}:${opts.prefixes.join(',')}`;
  const cached = repo.gitCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const keep = (name: string): boolean => opts.prefixes.length === 0 || opts.prefixes.some((prefix) => name.startsWith(prefix));
  const lines: string[] = [];
  const defaultRef = headTarget(repo);
  const tip = headTip(repo);
  if (keep('HEAD') && opts.symrefs) {
    if (tip === undefined) lines.push(`unborn HEAD symref-target:${defaultRef}\n`);
    else lines.push(`${tip} HEAD symref-target:${defaultRef}\n`);
  }
  for (const refname of sortedRefNames(repo)) {
    if (!keep(refname)) continue;
    const oid = repo.refs.get(refname) as string;
    let line = `${oid} ${refname}`;
    if (opts.peel && refname.startsWith('refs/tags/')) {
      const peeled = peelObject(oid);
      if (peeled !== oid) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  const buf = pktLines([...lines, 'flush']);
  repo.gitCache.set(cacheKey, buf);
  return buf;
}

// -------------------------------------------------------------------------------------------
// Fetch (v2): wants / haves / shallow / deepen
// -------------------------------------------------------------------------------------------

interface FetchRequest {
  wants: string[];
  haves: string[];
  shallow: string[];
  depth: number | null;
  deepenSince: number | null;
  deepenNot: string[];
}

interface FetchOutcome {
  response: Buffer;
}

/**
 * Compute the fetch: included commits, their objects, and the shallow-info lines.
 * Exclusion rule: objects reachable from a have are withheld, EXCEPT that a have which is also
 * a client shallow boundary withholds only itself (plus its tree/blobs) — its ancestors stay
 * deliverable, which is exactly what a deepen needs.
 */
// Split a want list into commit tips to walk from and non-commit objects to deliver
// as-is. A tag want is delivered itself and also walked from the commit it peels to.
function resolveWants(wants: readonly string[]): { tips: string[]; extras: string[] } {
  const tips: string[] = [];
  const extras: string[] = [];
  for (const want of wants) {
    const obj = objects.get(want);
    if (obj === undefined) continue;
    if (obj.type === 'commit') tips.push(want);
    else if (obj.type === 'tag') {
      extras.push(want);
      const target = peelObject(want);
      if (target !== want && objects.get(target)?.type === 'commit') tips.push(target);
    } else {
      extras.push(want);
    }
  }
  return { tips, extras };
}

function computeFetch(repo: Repo, req: FetchRequest): { entries: ParsedPackEntry[]; shallow: string[]; unshallow: string[]; acks: string[] } {
  const shallowSet = new Set(req.shallow);
  const haveSet = new Set(req.haves);
  // Commits excluded from the walk: everything reachable from a non-shallow have, plus the shallow
  // boundaries themselves.
  const excludedCommits = new Set<string>();
  for (const have of haveSet) {
    if (shallowSet.has(have)) {
      excludedCommits.add(have);
    } else {
      for (const oid of reachableCommits([have])) excludedCommits.add(oid);
    }
  }
  for (const ref of req.deepenNot) {
    const oid = repo.refs.get(ref) ?? (isOid(ref) ? ref : undefined);
    if (oid !== undefined) for (const c of reachableCommits([oid])) excludedCommits.add(c);
  }
  // Resolve wants: commits are walked; a tag want is delivered itself and walked from
  // the commit it peels to; any other object want is delivered as-is.
  const { tips: walkTips, extras: extraObjects } = resolveWants(req.wants);
  // Walk from the wants with the depth / date cutoff.
  const included: string[] = [];
  const seen = new Set<string>();
  const queue: Array<{ oid: string; depth: number }> = walkTips.map((oid) => ({ oid, depth: 1 }));
  while (queue.length > 0) {
    const { oid, depth } = queue.shift() as { oid: string; depth: number };
    if (seen.has(oid)) continue;
    seen.add(oid);
    const info = parseCommit(oid);
    if (info === null) continue;
    if (req.deepenSince !== null && info.timestamp <= req.deepenSince) continue;
    if (!excludedCommits.has(oid)) included.push(oid);
    const cut = (req.depth !== null && depth >= req.depth) || (req.deepenSince !== null && info.timestamp <= req.deepenSince);
    if (cut) continue;
    for (const parent of info.parents) {
      if (!seen.has(parent)) queue.push({ oid: parent, depth: depth + 1 });
    }
  }
  const includedSet = new Set(included);
  // Shallow boundary: an included commit with at least one parent that is not included.
  const shallow: string[] = [];
  for (const oid of included) {
    const info = parseCommit(oid);
    if (info !== null && info.parents.length > 0 && info.parents.some((parent) => !includedSet.has(parent))) shallow.push(oid);
  }
  // Unshallow: a former client boundary whose parents are all included now.
  const unshallow: string[] = [];
  for (const oid of req.shallow) {
    const info = parseCommit(oid);
    if (info === null) continue;
    if (info.parents.length === 0) continue;
    if (info.parents.every((parent) => includedSet.has(parent))) unshallow.push(oid);
  }
  // Object closure of the included commits, minus objects the client already holds.
  // Held set: for a plain have, the full reachable closure; for a shallow boundary, only the
  // boundary commit plus its tree/blobs (its ancestors are NOT held — that is what a deepen is for).
  const heldObjects = new Set<string>();
  for (const have of haveSet) {
    if (shallowSet.has(have)) {
      heldObjects.add(have);
      const info = parseCommit(have);
      if (info !== null) {
        heldObjects.add(info.tree);
        for (const entry of collectFetchObjects([info.tree])) heldObjects.add(entry.oid);
      }
    } else {
      for (const entry of collectFetchObjects(reachableCommits([have]))) heldObjects.add(entry.oid);
    }
  }
  const wantObjects = collectFetchObjects([...included, ...extraObjects]);
  const entries = wantObjects.filter((entry) => !heldObjects.has(entry.oid));
  const acks: string[] = [];
  for (const have of req.haves) {
    if (objects.has(have)) acks.push(have);
  }
  return { entries, shallow, unshallow, acks };
}

function fetchV2Response(repo: Repo, req: FetchRequest): Buffer {
  const cacheKey = `fetch:${req.wants.join(',')}|${req.haves.join(',')}|${req.shallow.join(',')}|${req.depth ?? ''}|${req.deepenSince ?? ''}|${req.deepenNot.join(',')}`;
  const cached = repo.gitCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const { entries, shallow, unshallow, acks } = computeFetch(repo, req);
  const parts: Buffer[] = [];
  const ackLines = acks.length > 0 ? [...acks.map((oid) => `ACK ${oid}\n`), 'ready\n'] : ['NAK\n'];
  parts.push(pktLines(['acknowledgments\n', ...ackLines, 'delim']));
  if (shallow.length > 0 || unshallow.length > 0) {
    const infoLines = [
      ...shallow.map((oid) => `shallow ${oid}\n`),
      ...unshallow.map((oid) => `unshallow ${oid}\n`),
    ];
    parts.push(pktLines(['shallow-info\n', ...infoLines, 'delim']));
  }
  // wanted-refs: map each want oid back to a ref tip when known.
  const refByOid = new Map<string, string>();
  for (const [refname, oid] of repo.refs) {
    if (!refByOid.has(oid)) refByOid.set(oid, refname);
  }
  const wanted = req.wants.filter((oid) => refByOid.has(oid));
  if (wanted.length > 0) {
    parts.push(pktLines(['wanted-refs\n', ...wanted.map((oid) => `${oid} ${refByOid.get(oid) as string}\n`), 'delim']));
  }
  if (entries.length > 0) {
    const pack = buildPack(entries);
    const section = Buffer.concat([pktLine('packfile\n'), ...sidebandChunks(pack)]);
    parts.push(section);
  }
  parts.push(PKT_FLUSH);
  const buf = Buffer.concat(parts);
  repo.gitCache.set(cacheKey, buf);
  return buf;
}

/** Minimal v0 fetch: want lines, NAK, then the pack in sideband band 1. */
function fetchV0Response(repo: Repo, lines: string[]): Buffer {
  const wants: string[] = [];
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text.startsWith('want ')) {
      const oid = text.slice(5).split(' ')[0] as string;
      if (isOid(oid)) wants.push(oid);
    }
  }
  const { tips, extras } = resolveWants(wants);
  const included = reachableCommits(tips);
  const entries = collectFetchObjects([...included, ...extras]);
  const parts: Buffer[] = [pktLine('NAK\n')];
  if (entries.length > 0) parts.push(...sidebandChunks(buildPack(entries)));
  parts.push(PKT_FLUSH);
  return Buffer.concat(parts);
}

/** Parse a v2 ls-refs / fetch request body into its argument lines. */
function parseV2Args(body: Buffer): { command: string; args: string[] } {
  const packets = decodePackets(body);
  const lines: string[] = [];
  for (const packet of packets) {
    if (packet.kind === 'data') lines.push(packet.payload.toString('utf8'));
  }
  const command = (lines[0] ?? '').replace(/\n$/, '');
  return { command, args: lines.slice(1) };
}

function handleUploadPack(repo: Repo, body: Buffer): { status: number; contentType: string; body: Buffer } {
  const { command, args } = parseV2Args(body);
  if (command === 'command=ls-refs') {
    const opts: LsRefsOptions = { peel: false, symrefs: false, unborn: false, prefixes: [] };
    for (const raw of args) {
      const line = raw.replace(/\n$/, '');
      if (line === 'peel') opts.peel = true;
      else if (line === 'symrefs') opts.symrefs = true;
      else if (line === 'unborn') opts.unborn = true;
      else if (line.startsWith('ref-prefix ')) opts.prefixes.push(line.slice('ref-prefix '.length));
    }
    return { status: 200, contentType: 'application/x-git-upload-pack-result', body: lsRefsResponse(repo, opts) };
  }
  if (command === 'command=fetch') {
    const req: FetchRequest = { wants: [], haves: [], shallow: [], depth: null, deepenSince: null, deepenNot: [] };
    for (const raw of args) {
      const line = raw.replace(/\n$/, '');
      if (line.startsWith('want ')) req.wants.push(line.slice(5).trim());
      else if (line.startsWith('have ')) req.haves.push(line.slice(5).trim());
      else if (line.startsWith('shallow ')) req.shallow.push(line.slice(8).trim());
      else if (line.startsWith('deepen ')) req.depth = Number(line.slice(7).trim());
      else if (line.startsWith('deepen-since ')) req.deepenSince = Number(line.slice(13).trim());
      else if (line.startsWith('deepen-not ')) req.deepenNot.push(line.slice(11).trim());
    }
    return { status: 200, contentType: 'application/x-git-upload-pack-result', body: fetchV2Response(repo, req) };
  }
  // v0 fetch: want/have lines with no command.
  const lines = [command, ...args];
  return { status: 200, contentType: 'application/x-git-upload-pack-result', body: fetchV0Response(repo, lines) };
}

// -------------------------------------------------------------------------------------------
// Receive-pack (push)
// -------------------------------------------------------------------------------------------

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(repo: Repo, body: Buffer): { status: number; contentType: string; body: Buffer } {
  const { lines, rawStart } = readPktLines(body);
  const commands: PushCommand[] = [];
  for (const raw of lines) {
    const line = raw.replace(/\n$/, '');
    const nul = line.indexOf('\0');
    const head = nul >= 0 ? line.slice(0, nul) : line;
    const parts = head.split(' ');
    if (parts.length < 3) continue;
    const [oldOid, newOid, ref] = parts as [string, string, string];
    if (isOid(oldOid) && isOid(newOid)) commands.push({ oldOid, newOid, ref });
  }
  // The pack follows the terminating flush packet (rawStart points at it).
  const packStart = rawStart + 4;
  const packBytes = packStart < body.length ? body.subarray(packStart) : Buffer.alloc(0);
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  let unpackOk = true;
  if (packBytes.length > 0) {
    try {
      parsePack(packBytes);
    } catch (err) {
      unpackOk = false;
    }
  }
  if (!unpackOk) {
    const report = pktLines(['unpack error\n', ...commands.map((cmd) => `ng ${cmd.ref} unpacker error\n`), 'flush']);
    return { status: 200, contentType: 'application/x-git-receive-pack-result', body: Buffer.concat([...sidebandChunks(report), PKT_FLUSH]) };
  }
  for (const cmd of commands) {
    if (cmd.newOid === ZERO_OID) {
      // Delete the ref.
      if (repo.refs.has(cmd.ref)) {
        repo.refs.delete(cmd.ref);
        clearGitCache(repo);
        results.push({ ref: cmd.ref, ok: true, reason: '' });
      } else {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
      }
      continue;
    }
    const current = repo.refs.get(cmd.ref);
    if (current !== undefined && current !== cmd.oldOid) {
      results.push({ ref: cmd.ref, ok: false, reason: 'remote ref updated since checkout' });
      continue;
    }
    if (current === undefined) {
      // Create: old must be zero, new object must exist.
      if (cmd.oldOid !== ZERO_OID) {
        results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
        continue;
      }
      if (!objects.has(cmd.newOid)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      clearGitCache(repo);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      continue;
    }
    // Update: must be a fast-forward (or a force-free same-value no-op).
    if (cmd.newOid === current) {
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      continue;
    }
    if (!objects.has(cmd.newOid) || !isAncestor(current, cmd.newOid)) {
      results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    repo.refs.set(cmd.ref, cmd.newOid);
    clearGitCache(repo);
    results.push({ ref: cmd.ref, ok: true, reason: '' });
  }
  const reportLines: string[] = ['unpack ok\n'];
  for (const result of results) {
    reportLines.push(result.ok ? `ok ${result.ref}\n` : `ng ${result.ref} ${result.reason}\n`);
  }
  const report = pktLines([...reportLines, 'flush']);
  return { status: 200, contentType: 'application/x-git-receive-pack-result', body: Buffer.concat([...sidebandChunks(report), PKT_FLUSH]) };
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing
// -------------------------------------------------------------------------------------------

type HttpRes = http.ServerResponse<http.IncomingMessage>;

function setCommonHeaders(res: HttpRes, contentType: string): void {
  res.setHeader('content-type', contentType);
  res.setHeader('x-github-request-id', nextRequestId());
  res.setHeader('x-oauth-scopes', 'repo');
}

function sendJson(res: HttpRes, status: number, value: unknown, extra: Record<string, string> = {}): void {
  setCommonHeaders(res, 'application/json');
  for (const [key, val] of Object.entries(extra)) res.setHeader(key, val);
  const body = typeof value === 'string' ? value : JSON.stringify(value);
  res.writeHead(status);
  res.end(body);
}

function sendRaw(res: HttpRes, status: number, contentType: string, body: Buffer): void {
  res.setHeader('content-type', contentType);
  res.setHeader('x-github-request-id', nextRequestId());
  res.writeHead(status);
  res.end(body);
}

function sendError(res: HttpRes, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 64 * 1024 * 1024) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(body: Buffer): unknown {
  if (body.length === 0) return {};
  return JSON.parse(body.toString('utf8'));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkAuth(req: http.IncomingMessage): boolean {
  return req.headers.authorization === EXPECTED_AUTH;
}

/** Paginate an array (GitHub style): page/per_page + a Link header. */
function paginate<T>(
  req: http.IncomingMessage,
  res: HttpRes,
  items: readonly T[],
  query: URLSearchParams,
): T[] {
  const perPageRaw = Number(query.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, Math.trunc(perPageRaw))) : 30;
  const pageRaw = Number(query.get('page') ?? '1');
  const page = Number.isFinite(pageRaw) ? Math.max(1, Math.trunc(pageRaw)) : 1;
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  const host = req.headers.host ?? '127.0.0.1';
  const path = req.url?.split('?')[0] ?? '';
  const linkFor = (p: number): string => `http://${host}${path}?per_page=${perPage}&page=${p}`;
  const links: string[] = [];
  if (page < totalPages) links.push(`<${linkFor(page + 1)}>; rel="next"`);
  if (page > 1) links.push(`<${linkFor(page - 1)}>; rel="prev"`);
  links.push(`<${linkFor(1)}>; rel="first"`);
  links.push(`<${linkFor(totalPages)}>; rel="last"`);
  res.setHeader('link', links.join(', '));
  return items.slice(start, start + perPage);
}

function sortIssues(issues: Issue[], query: URLSearchParams): Issue[] {
  const direction = (query.get('direction') ?? 'desc').toLowerCase() === 'asc' ? 1 : -1;
  return [...issues].sort((a, b) => (a.createdSeq - b.createdSeq) * direction);
}

function sortPulls(pulls: Pull[]): Pull[] {
  return [...pulls].sort((a, b) => b.createdSeq - a.createdSeq);
}

// -------------------------------------------------------------------------------------------
// REST v3
// -------------------------------------------------------------------------------------------

let nextGlobalIssueId = 1;
let nextGlobalPullId = 1;
let nextGlobalCommentId = 1;

function createIssueRecord(repo: Repo, title: string, body: string, labels: string[]): Issue {
  const number = repo.nextIssue;
  repo.nextIssue += 1;
  const issue: Issue = {
    number,
    id: nextGlobalIssueId,
    title,
    body,
    state: 'open',
    labels: [...labels],
    comments: [],
    createdSeq: (globalSeq += 1),
    jsonStr: '',
  };
  nextGlobalIssueId += 1;
  issue.jsonStr = issueJsonString(issue);
  repo.issues.set(number, issue);
  globalIdRegistry.set(issueGlobalId(repo, number), { kind: 'issue', owner: repo.owner, repo: repo.name, number });
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, headRef: string, baseRef: string): Pull {
  const number = repo.nextPull;
  repo.nextPull += 1;
  const pull: Pull = {
    number,
    id: nextGlobalPullId,
    title,
    body,
    state: 'open',
    headRef,
    baseRef,
    headSha: repo.refs.get(`refs/heads/${headRef}`) ?? ZERO_OID,
    baseSha: repo.refs.get(`refs/heads/${baseRef}`) ?? ZERO_OID,
    merged: false,
    mergedAt: null,
    mergeSha: null,
    createdSeq: (globalSeq += 1),
    jsonStr: '',
  };
  nextGlobalPullId += 1;
  pull.jsonStr = pullJsonString(pull);
  repo.pulls.set(number, pull);
  globalIdRegistry.set(pullGlobalId(repo, number), { kind: 'pull', owner: repo.owner, repo: repo.name, number });
  return pull;
}

/** Resolve a ref-ish (branch name or full oid) to a commit oid, or null. */
function resolveRefToCommit(repo: Repo, ref: string | null): string | null {
  if (ref === null || ref === '') return headTip(repo) ?? null;
  const branchTip = repo.refs.get(`refs/heads/${ref}`);
  if (branchTip !== undefined) return branchTip;
  const tagTip = repo.refs.get(`refs/tags/${ref}`);
  if (tagTip !== undefined) return peelObject(tagTip);
  if (isOid(ref) && objects.has(ref)) return ref;
  const direct = repo.refs.get(ref);
  if (direct !== undefined) return direct;
  return null;
}

async function handleRest(req: http.IncomingMessage, res: HttpRes, segments: string[], query: URLSearchParams): Promise<void> {
  const method = (req.method ?? 'GET').toUpperCase();
  // Root and meta are public; everything else under /api/v3 needs the trial token.
  const isPublic = (segments.length === 0 && method === 'GET') || (segments.length === 1 && segments[0] === 'meta' && method === 'GET');
  if (!isPublic && !checkAuth(req)) {
    sendError(res, 401, 'Requires authentication');
    return;
  }
  const body = method === 'GET' || method === 'HEAD' ? Buffer.alloc(0) : await readBody(req);
  let json: unknown = {};
  if (body.length > 0) {
    try {
      json = parseJsonBody(body);
    } catch {
      sendError(res, 400, 'Problems parsing JSON');
      return;
    }
  }
  const input = isRecord(json) ? json : {};

  // GET /api/v3/ and /api/v3/meta
  if (segments.length === 0) {
    if (method !== 'GET') {
      sendError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { current_user_url: '/api/v3/user', message: 'github-core-clone' });
    return;
  }
  if (segments.length === 1 && segments[0] === 'meta') {
    sendJson(res, 200, { installed_version: INSTALL_VERSION });
    return;
  }
  if (segments.length === 1 && segments[0] === 'user' && method === 'GET') {
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return;
  }
  if (segments.length === 2 && segments[0] === 'user' && segments[1] === 'repos') {
    if (method === 'GET') {
      const mine = [...repos.values()].filter((repo) => repo.owner === VIEWER_LOGIN).sort((a, b) => a.createdSeq - b.createdSeq);
      const page = paginate(req, res, mine, query);
      sendJson(res, 200, page.map((repo) => repoJsonObject(repo)));
      return;
    }
    if (method === 'POST') {
      const name = typeof input.name === 'string' ? input.name : '';
      if (name === '') {
        sendError(res, 422, 'name is required');
        return;
      }
      if (findRepo(VIEWER_LOGIN, name) !== undefined) {
        sendError(res, 422, 'Repository already exists');
        return;
      }
      const description = typeof input.description === 'string' ? input.description : '';
      const isPrivate = input.private === true;
      const repo = createRepoRecord(VIEWER_LOGIN, name, description, isPrivate);
      sendJson(res, 201, repoJsonObject(repo));
      return;
    }
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (segments[0] === 'repos' && segments.length >= 3) {
    const owner = decodeURIComponent(segments[1] as string);
    const name = decodeURIComponent(segments[2] as string);
    if (owner !== VIEWER_LOGIN) {
      sendError(res, 404, 'Not Found');
      return;
    }
    const repo = findRepo(owner, name);
    const rest = segments.slice(3);
    if (repo === undefined) {
      sendError(res, 404, 'Not Found');
      return;
    }
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repo.repoJson);
        return;
      }
      if (method === 'PATCH') {
        if (typeof input.description === 'string') repo.description = input.description;
        if (typeof input.default_branch === 'string' && input.default_branch !== '') repo.defaultBranch = input.default_branch;
        refreshRepoJson(repo);
        clearGitCache(repo); // a default_branch change moves the symref HEAD target in cached advertisements
        sendJson(res, 200, repoJsonObject(repo));
        return;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, name));
        res.writeHead(204, { 'content-type': 'application/json', 'x-github-request-id': nextRequestId(), 'x-oauth-scopes': 'repo' });
        res.end();
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    const [head, ...tail] = rest as [string, ...string[]];
    if (head === 'branches' && method === 'GET') {
      if (tail.length === 0) {
        const list = [...repo.refs.keys()]
          .filter((refname) => refname.startsWith('refs/heads/'))
          .map((refname) => ({ name: refname.slice('refs/heads/'.length), commit: { sha: repo.refs.get(refname) as string } }))
          .sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, list);
        return;
      }
      const branch = decodeURIComponent(tail.join('/'));
      const tip = repo.refs.get(`refs/heads/${branch}`);
      if (tip === undefined) {
        sendError(res, 404, 'Branch not found');
        return;
      }
      sendJson(res, 200, { name: branch, commit: { sha: tip } });
      return;
    }
    if (head === 'commits' && method === 'GET') {
      const tip = resolveRefToCommit(repo, query.get('sha'));
      if (tip === null) {
        sendJson(res, 200, []);
        return;
      }
      const list = reachableCommits([tip]).map((oid) => {
        const info = parseCommit(oid);
        return {
          sha: oid,
          commit: {
            message: info?.message ?? '',
            author: { name: 'Forge', email: 'forge@example.invalid', date: FIXED_ISO },
            committer: { name: 'Forge', email: 'forge@example.invalid', date: FIXED_ISO },
          },
        };
      });
      sendJson(res, 200, list);
      return;
    }
    if (head === 'git' && tail[0] === 'refs') {
      if (method === 'GET' && tail[1] === 'heads' && tail.length >= 3) {
        const branch = decodeURIComponent(tail.slice(2).join('/'));
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, sha: tip, object: { sha: tip } });
        return;
      }
      if (method === 'POST' && tail.length === 1) {
        const ref = typeof input.ref === 'string' ? input.ref : '';
        const sha = typeof input.sha === 'string' ? input.sha : '';
        if (!ref.startsWith('refs/') || !isOid(sha) || !objects.has(sha)) {
          sendError(res, 422, 'Invalid ref or sha');
          return;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, 'Reference already exists');
          return;
        }
        repo.refs.set(ref, sha);
        clearGitCache(repo);
        sendJson(res, 201, { ref, sha, object: { sha } });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (head === 'contents') {
      const filePath = tail.map((segment) => decodeURIComponent(segment)).join('/');
      if (filePath === '') {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (method === 'GET') {
        const tip = resolveRefToCommit(repo, query.get('ref'));
        if (tip === null) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const treeOid = parseCommit(tip)?.tree ?? EMPTY_TREE_OID;
        const flat = flattenTree(treeOid);
        const file = flat.get(filePath);
        if (file !== undefined) {
          const obj = objects.get(file.oid);
          const data = obj?.data ?? Buffer.alloc(0);
          sendJson(res, 200, {
            type: 'file',
            encoding: 'base64',
            content: data.toString('base64'),
            sha: file.oid,
            size: data.length,
            name: filePath.split('/').pop() ?? filePath,
            path: filePath,
          });
          return;
        }
        // Directory listing: entries directly under this path.
        const prefix = `${filePath}/`;
        const entries: Array<{ type: string; name: string; path: string; sha: string }> = [];
        const seenDirs = new Set<string>();
        for (const [path, value] of flat) {
          if (!path.startsWith(prefix)) continue;
          const restPath = path.slice(prefix.length);
          const slash = restPath.indexOf('/');
          if (slash < 0) {
            entries.push({ type: 'file', name: restPath, path, sha: value.oid });
          } else {
            const dirName = restPath.slice(0, slash);
            if (!seenDirs.has(dirName)) {
              seenDirs.add(dirName);
              // Find the subtree oid for this directory.
              let dirTree = treeOid;
              for (const part of `${filePath}/${dirName}`.split('/')) {
                const partEntries = parseTree(dirTree);
                const found = partEntries?.find((entry) => entry.name === part && entry.mode === '40000');
                if (found === undefined) {
                  dirTree = EMPTY_TREE_OID;
                  break;
                }
                dirTree = found.oid;
              }
              entries.push({ type: 'dir', name: dirName, path: `${filePath}/${dirName}`, sha: dirTree });
            }
          }
        }
        if (entries.length === 0) {
          sendError(res, 404, 'Not Found');
          return;
        }
        entries.sort((a, b) => (a.name < b.name ? -1 : 1));
        sendJson(res, 200, entries);
        return;
      }
      if (method === 'PUT') {
        const message = typeof input.message === 'string' ? input.message : '';
        const contentB64 = typeof input.content === 'string' ? input.content : '';
        if (contentB64 === '') {
          sendError(res, 422, 'content is required');
          return;
        }
        const content = Buffer.from(contentB64.replace(/[\r\n\t ]+/g, ''), 'base64');
        const branch = typeof input.branch === 'string' && input.branch !== '' ? input.branch : repo.defaultBranch;
        if (!repo.refs.has(`refs/heads/${branch}`)) {
          // Creating a branch from the default tip (or an unborn repository).
          const base = headTip(repo);
          if (base !== undefined) repo.refs.set(`refs/heads/${branch}`, base);
        }
        const tip = repo.refs.get(`refs/heads/${branch}`);
        if (tip !== undefined) {
          const treeOid = parseCommit(tip)?.tree ?? EMPTY_TREE_OID;
          const existing = flattenTree(treeOid).get(filePath);
          if (existing !== undefined && typeof input.sha === 'string' && input.sha !== '' && input.sha !== existing.oid) {
            sendError(res, 409, 'sha does not match the current file');
            return;
          }
        }
        const result = commitFile(repo, branch, filePath, content, message);
        sendJson(res, result.isNew ? 201 : 200, {
          content: { name: filePath.split('/').pop() ?? filePath, path: filePath, sha: result.contentSha, size: content.length, encoding: 'base64', type: 'file' },
          commit: { sha: result.commitSha },
        });
        return;
      }
      if (method === 'DELETE') {
        const message = typeof input.message === 'string' ? input.message : '';
        const tip = headTip(repo);
        if (tip === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const treeOid = parseCommit(tip)?.tree ?? EMPTY_TREE_OID;
        if (!flattenTree(treeOid).has(filePath)) {
          sendError(res, 404, 'Not Found');
          return;
        }
        const commitSha = deleteFile(repo, repo.defaultBranch, filePath, message);
        if (commitSha === null) {
          sendError(res, 404, 'Not Found');
          return;
        }
        sendJson(res, 200, { commit: { sha: commitSha } });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (head === 'labels' && method === 'POST') {
      const labelName = typeof input.name === 'string' ? input.name : '';
      if (labelName === '') {
        sendError(res, 422, 'name is required');
        return;
      }
      repo.labels.add(labelName);
      sendJson(res, 201, { name: labelName });
      return;
    }
    if (head === 'issues') {
      if (tail.length === 0) {
        if (method === 'GET') {
          const state = (query.get('state') ?? 'open').toLowerCase();
          let list = [...repo.issues.values()];
          if (state === 'open') list = list.filter((issue) => issue.state === 'open');
          else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
          list = sortIssues(list, query);
          const page = paginate(req, res, list, query);
          sendJson(res, 200, `[${page.map((issue) => issue.jsonStr).join(',')}]`);
          return;
        }
        if (method === 'POST') {
          const title = typeof input.title === 'string' ? input.title : '';
          const bodyText = typeof input.body === 'string' ? input.body : '';
          const labels = Array.isArray(input.labels) ? (input.labels.filter((entry) => typeof entry === 'string') as string[]) : [];
          for (const label of labels) {
            if (!repo.labels.has(label)) {
              sendError(res, 422, `Label does not exist: ${label}`);
              return;
            }
          }
          const issue = createIssueRecord(repo, title, bodyText, labels);
          sendJson(res, 201, issue.jsonStr);
          return;
        }
      }
      const number = Number(tail[0]);
      if (!Number.isInteger(number) || number < 1) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const issue = repo.issues.get(number);
      if (tail.length === 1) {
        if (issue === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.jsonStr);
          return;
        }
        if (method === 'PATCH') {
          const state = typeof input.state === 'string' ? input.state : '';
          if (state === 'open' || state === 'closed') issue.state = state;
          if (typeof input.title === 'string') issue.title = input.title;
          if (typeof input.body === 'string') issue.body = input.body;
          issue.jsonStr = issueJsonString(issue);
          sendJson(res, 200, issue.jsonStr);
          return;
        }
        sendError(res, 404, 'Not Found');
        return;
      }
      if (tail[1] === 'comments') {
        if (issue === undefined) {
          sendError(res, 404, 'Not Found');
          return;
        }
        if (method === 'GET') {
          sendJson(res, 200, issue.comments.map((comment) => ({ id: comment.id, body: comment.body })));
          return;
        }
        if (method === 'POST') {
          const commentBody = typeof input.body === 'string' ? input.body : '';
          const comment = { id: nextGlobalCommentId, body: commentBody };
          nextGlobalCommentId += 1;
          issue.comments.push(comment);
          globalIdRegistry.set(commentGlobalId(repo, number, comment.id), { kind: 'comment', owner, repo: name, number });
          sendJson(res, 201, { id: comment.id, body: comment.body });
          return;
        }
      }
      sendError(res, 404, 'Not Found');
      return;
    }
    if (head === 'pulls') {
      if (tail.length === 0) {
        if (method === 'GET') {
          const state = (query.get('state') ?? 'open').toLowerCase();
          let list = [...repo.pulls.values()];
          if (state === 'open') list = list.filter((pull) => pull.state === 'open');
          else if (state === 'closed') list = list.filter((pull) => pull.state === 'closed');
          list = sortPulls(list);
          const page = paginate(req, res, list, query);
          sendJson(res, 200, `[${page.map((pull) => pull.jsonStr).join(',')}]`);
          return;
        }
        if (method === 'POST') {
          const title = typeof input.title === 'string' ? input.title : '';
          const bodyText = typeof input.body === 'string' ? input.body : '';
          const headRef = typeof input.head === 'string' ? input.head : '';
          const baseRef = typeof input.base === 'string' ? input.base : repo.defaultBranch;
          if (!repo.refs.has(`refs/heads/${headRef}`) || !repo.refs.has(`refs/heads/${baseRef}`)) {
            sendError(res, 422, 'Head or base branch does not exist');
            return;
          }
          const duplicate = [...repo.pulls.values()].find((pull) => pull.headRef === headRef && pull.state === 'open');
          if (duplicate !== undefined) {
            sendError(res, 422, 'A pull request already exists for this head branch');
            return;
          }
          const pull = createPullRecord(repo, title, bodyText, headRef, baseRef);
          sendJson(res, 201, pull.jsonStr);
          return;
        }
      }
      const number = Number(tail[0]);
      if (!Number.isInteger(number) || number < 1) {
        sendError(res, 404, 'Not Found');
        return;
      }
      const pull = repo.pulls.get(number);
      if (pull === undefined) {
        sendError(res, 404, 'Not Found');
        return;
      }
      if (tail.length === 1 && method === 'GET') {
        sendJson(res, 200, pull.jsonStr);
        return;
      }
      if (tail.length === 2 && tail[1] === 'files' && method === 'GET') {
        sendJson(res, 200, pullFiles(repo, pull));
        return;
      }
      if (tail.length === 2 && tail[1] === 'merge' && method === 'PUT') {
        if (pull.state === 'closed') {
          sendError(res, 409, 'Pull request is already closed');
          return;
        }
        const outcome = squashMerge(repo, pull, `Merge pull request #${pull.number} from ${pull.headRef}`);
        if (outcome.conflict || outcome.commitSha === null) {
          sendError(res, 405, 'Merge conflict');
          return;
        }
        pull.state = 'closed';
        pull.merged = true;
        pull.mergedAt = FIXED_ISO;
        pull.mergeSha = outcome.commitSha;
        pull.jsonStr = pullJsonString(pull);
        sendJson(res, 200, { sha: outcome.commitSha, merged: true, message: `Pull request #${pull.number} merged` });
        return;
      }
      sendError(res, 404, 'Not Found');
      return;
    }
  }
  sendError(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// GraphQL v4 (small parser + executor for the documents gh / github-mcp-server send)
// -------------------------------------------------------------------------------------------

interface GqlSelection {
  alias: string | null;
  name: string;
  args: Record<string, unknown>;
  selections: GqlSelection[] | null;
  fragmentType: string | null; // set for `... on Type`
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  fields: GqlSelection[];
}

type GqlToken =
  | { kind: 'name'; value: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'punct'; value: string }
  | { kind: 'spread'; value: string };

function tokenizeGql(source: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < source.length) {
    const ch = source[i] as string;
    if (ch === ' ' || ch === '\n' || ch === '\t' || ch === '\r' || ch === ',' || ch === '#') {
      if (ch === '#') {
        while (i < source.length && source[i] !== '\n') i += 1;
      } else i += 1;
      continue;
    }
    if (ch === '.' && source.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'spread', value: '...' });
      i += 3;
      continue;
    }
    if ('{}():$![]=<>|&'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < source.length && source[j] !== '"') {
        if (source[j] === '\\' && j + 1 < source.length) {
          const esc = source[j + 1] as string;
          out += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          j += 2;
        } else {
          out += source[j] as string;
          j += 1;
        }
      }
      tokens.push({ kind: 'string', value: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < source.length && /[0-9]/.test(source[j] as string)) j += 1;
      tokens.push({ kind: 'int', value: Number(source.slice(i, j)) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < source.length && /[A-Za-z0-9_]/.test(source[j] as string)) j += 1;
      tokens.push({ kind: 'name', value: source.slice(i, j) });
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private pos = 0;
  private readonly tokens: GqlToken[];
  constructor(tokens: GqlToken[]) {
    this.tokens = tokens;
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }
  private next(): GqlToken {
    const tok = this.tokens[this.pos];
    if (tok === undefined) throw new Error('unexpected end of GraphQL document');
    this.pos += 1;
    return tok;
  }
  private expectPunct(value: string): void {
    const tok = this.next();
    if (tok.kind !== 'punct' || tok.value !== value) throw new Error(`expected ${value} in GraphQL document`);
  }
  private expectName(value?: string): string {
    const tok = this.next();
    if (tok.kind !== 'name') throw new Error('expected a name in GraphQL document');
    if (value !== undefined && tok.value !== value) throw new Error(`expected ${value} in GraphQL document`);
    return tok.value;
  }

  parseDocument(): GqlOperation[] {
    const ops: GqlOperation[] = [];
    while (this.pos < this.tokens.length) {
      const tok = this.peek() as GqlToken;
      if (tok.kind === 'punct' && tok.value === '{') {
        ops.push({ kind: 'query', name: null, fields: this.parseSelectionSet() });
        continue;
      }
      if (tok.kind === 'name' && (tok.value === 'query' || tok.value === 'mutation')) {
        const kind = tok.value as 'query' | 'mutation';
        this.next();
        let name: string | null = null;
        const maybeName = this.peek();
        if (maybeName !== undefined && maybeName.kind === 'name') name = this.next().value as string;
        // Skip variable definitions: ($x: Type = default, ...)
        const maybeParen = this.peek();
        if (maybeParen !== undefined && maybeParen.kind === 'punct' && maybeParen.value === '(') this.skipBalanced('(', ')');
        ops.push({ kind, name, fields: this.parseSelectionSet() });
        continue;
      }
      if (tok.kind === 'name' && tok.value === 'fragment') {
        throw new Error('named fragments are not supported');
      }
      this.next();
    }
    return ops;
  }

  private skipBalanced(open: string, close: string): void {
    let depth = 0;
    for (;;) {
      const tok = this.next();
      if (tok.kind === 'punct' && tok.value === open) depth += 1;
      else if (tok.kind === 'punct' && tok.value === close) {
        depth -= 1;
        if (depth === 0) return;
      }
    }
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const fields: GqlSelection[] = [];
    for (;;) {
      const tok = this.peek();
      if (tok === undefined) throw new Error('unterminated selection set');
      if (tok.kind === 'punct' && tok.value === '}') {
        this.next();
        return fields;
      }
      if (tok.kind === 'spread') {
        this.next();
        const onTok = this.peek();
        let fragmentType: string | null = null;
        if (onTok !== undefined && onTok.kind === 'name' && onTok.value === 'on') {
          this.next();
          fragmentType = this.expectName();
        } else {
          throw new Error('named fragment spreads are not supported');
        }
        const selections = this.parseSelectionSet();
        fields.push({ alias: null, name: '', args: {}, selections, fragmentType });
        continue;
      }
      const first = this.expectName();
      let alias: string | null = null;
      let name = first;
      const colon = this.peek();
      if (colon !== undefined && colon.kind === 'punct' && colon.value === ':') {
        this.next();
        alias = first;
        name = this.expectName();
      }
      let args: Record<string, unknown> = {};
      const maybeArgs = this.peek();
      if (maybeArgs !== undefined && maybeArgs.kind === 'punct' && maybeArgs.value === '(') {
        args = this.parseArguments();
      }
      let selections: GqlSelection[] | null = null;
      const maybeSet = this.peek();
      if (maybeSet !== undefined && maybeSet.kind === 'punct' && maybeSet.value === '{') {
        selections = this.parseSelectionSet();
      }
      fields.push({ alias, name, args, selections, fragmentType: null });
    }
  }

  private parseArguments(): Record<string, unknown> {
    this.expectPunct('(');
    const args: Record<string, unknown> = {};
    for (;;) {
      const tok = this.peek();
      if (tok === undefined) throw new Error('unterminated arguments');
      if (tok.kind === 'punct' && tok.value === ')') {
        this.next();
        return args;
      }
      const name = this.expectName();
      this.expectPunct(':');
      args[name] = this.parseValue();
    }
  }

  private parseValue(): unknown {
    const tok = this.next();
    if (tok.kind === 'punct' && tok.value === '$') return { __var: this.expectName() };
    if (tok.kind === 'punct' && tok.value === '[') {
      const list: unknown[] = [];
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new Error('unterminated list');
        if (next.kind === 'punct' && next.value === ']') {
          this.next();
          return list;
        }
        list.push(this.parseValue());
      }
    }
    if (tok.kind === 'punct' && tok.value === '{') {
      const obj: Record<string, unknown> = {};
      for (;;) {
        const next = this.peek();
        if (next === undefined) throw new Error('unterminated input object');
        if (next.kind === 'punct' && next.value === '}') {
          this.next();
          return obj;
        }
        const name = this.expectName();
        this.expectPunct(':');
        obj[name] = this.parseValue();
      }
    }
    if (tok.kind === 'string') return tok.value;
    if (tok.kind === 'int') return tok.value;
    if (tok.kind === 'name') {
      if (tok.value === 'true') return true;
      if (tok.value === 'false') return false;
      if (tok.value === 'null') return null;
      return { __enum: tok.value };
    }
    throw new Error('unexpected value in GraphQL document');
  }
}

function resolveVariables(value: unknown, variables: Record<string, unknown>): unknown {
  if (isRecord(value) && '__var' in value) return variables[value.__var as string] ?? null;
  if (isRecord(value) && '__enum' in value) return value.__enum as string;
  if (Array.isArray(value)) return value.map((entry) => resolveVariables(entry, variables));
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) out[key] = resolveVariables(entry, variables);
    return out;
  }
  return value;
}

const INTROSPECTION_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'body', 'state', 'author', 'createdAt', 'updatedAt', 'comments', 'labels', 'closedAt', 'url'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'commits', 'reviews', 'createdAt', 'updatedAt', 'url'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'createdAt', 'updatedAt', 'url'],
  SearchType: [],
};
const SEARCH_TYPE_ENUMS = ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER', 'DISCUSSION', 'COMMIT'];

function issueStateGql(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}
function pullStateGql(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function issueCursor(number: number): string {
  return b64url(`n:${number}`);
}
function cursorNumber(cursor: string): number | null {
  try {
    const text = unb64url(cursor);
    const match = /^n:(\d+)$/.exec(text);
    return match === null ? null : Number(match[1]);
  } catch {
    return null;
  }
}

interface GqlContext {
  errors: Array<{ message: string }>;
}

function resolveIssueFields(issue: Issue, repo: Repo, selections: GqlSelection[], ctx: GqlContext): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    const key = sel.alias ?? sel.name;
    switch (sel.name) {
      case 'id':
        out[key] = issueGlobalId(repo, issue.number);
        break;
      case 'number':
        out[key] = issue.number;
        break;
      case 'title':
        out[key] = issue.title;
        break;
      case 'body':
        out[key] = issue.body;
        break;
      case 'state':
        out[key] = issueStateGql(issue);
        break;
      default:
        ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "Issue".` });
        break;
    }
  }
  return out;
}

function resolvePullFields(pull: Pull, repo: Repo, selections: GqlSelection[], ctx: GqlContext): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    const key = sel.alias ?? sel.name;
    switch (sel.name) {
      case 'id':
        out[key] = pullGlobalId(repo, pull.number);
        break;
      case 'number':
        out[key] = pull.number;
        break;
      case 'title':
        out[key] = pull.title;
        break;
      case 'body':
        out[key] = pull.body;
        break;
      case 'state':
        out[key] = pullStateGql(pull);
        break;
      case 'merged':
        out[key] = pull.merged;
        break;
      case 'headRefName':
        out[key] = pull.headRef;
        break;
      case 'baseRefName':
        out[key] = pull.baseRef;
        break;
      case 'mergeable':
        out[key] = pullWouldConflict(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
        break;
      case 'files': {
        const first = typeof sel.args.first === 'number' ? sel.args.first : 100;
        const files = pullFiles(repo, pull).slice(0, first);
        const nodesSel = (sel.selections ?? []).find((s) => s.name === 'nodes');
        const nodeFields = nodesSel?.selections ?? [];
        const nodes = files.map((file) => {
          const node: Record<string, unknown> = {};
          for (const sub of nodeFields) {
            if (sub.name === 'path') node[sub.alias ?? sub.name] = file.filename;
          }
          return node;
        });
        out[key] = { nodes };
        break;
      }
      default:
        ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "PullRequest".` });
        break;
    }
  }
  return out;
}

function resolveRepositoryFields(repo: Repo, selections: GqlSelection[], ctx: GqlContext, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    const key = sel.alias ?? sel.name;
    const args = resolveVariables(sel.args, variables) as Record<string, unknown>;
    switch (sel.name) {
      case 'id':
        out[key] = repoGlobalId(repo);
        break;
      case 'databaseId':
        out[key] = repo.id;
        break;
      case 'name':
        out[key] = repo.name;
        break;
      case 'nameWithOwner':
        out[key] = repoKey(repo.owner, repo.name);
        break;
      case 'owner': {
        const owner: Record<string, unknown> = {};
        for (const sub of sel.selections ?? []) {
          if (sub.name === 'login') owner[sub.alias ?? sub.name] = repo.owner;
          else ctx.errors.push({ message: `Cannot query field "${sub.name}" on type "User".` });
        }
        out[key] = owner;
        break;
      }
      case 'defaultBranchRef': {
        const ref: Record<string, unknown> = {};
        for (const sub of sel.selections ?? []) {
          if (sub.name === 'name') ref[sub.alias ?? sub.name] = repo.defaultBranch;
          else ctx.errors.push({ message: `Cannot query field "${sub.name}" on type "Ref".` });
        }
        out[key] = ref;
        break;
      }
      case 'viewerPermission':
        out[key] = 'ADMIN';
        break;
      case 'hasIssuesEnabled':
        out[key] = true;
        break;
      case 'description':
        out[key] = repo.description;
        break;
      case 'private':
        out[key] = repo.private;
        break;
      case 'issue': {
        const number = args.number as number | undefined;
        const issue = typeof number === 'number' ? repo.issues.get(number) : undefined;
        out[key] = issue === undefined ? null : resolveIssueFields(issue, repo, sel.selections ?? [], ctx);
        break;
      }
      case 'issues': {
        const first = typeof args.first === 'number' ? args.first : undefined;
        const states = Array.isArray(args.states) ? (args.states as string[]) : null;
        const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
        const after = typeof args.after === 'string' ? args.after : null;
        let list = [...repo.issues.values()];
        if (states !== null) {
          const wanted = new Set(states.map((state) => String(state).toUpperCase()));
          list = list.filter((issue) => wanted.has(issueStateGql(issue)));
        }
        const direction = orderBy !== null && String(orderBy.direction ?? '').toUpperCase() === 'ASC' ? 1 : -1;
        list.sort((a, b) => (a.number - b.number) * direction);
        if (after !== null) {
          const afterNumber = cursorNumber(after);
          if (afterNumber !== null) {
            list = list.filter((issue) => (direction === 1 ? issue.number > afterNumber : issue.number < afterNumber));
          }
        }
        const total = list.length;
        const page = first !== undefined ? list.slice(0, first) : list;
        const nodes: unknown[] = [];
        let pageInfo: Record<string, unknown> = { hasNextPage: false, endCursor: null };
        for (const issue of page) {
          nodes.push(resolveIssueFields(issue, repo, (sel.selections ?? []).filter((sub) => sub.name === 'nodes').flatMap((sub) => sub.selections ?? []), ctx));
        }
        // The selections of `issues` are { nodes { ... }, pageInfo { ... } }; resolve them directly.
        const conn: Record<string, unknown> = {};
        for (const sub of sel.selections ?? []) {
          if (sub.name === 'nodes') {
            conn[sub.alias ?? sub.name] = page.map((issue) => resolveIssueFields(issue, repo, sub.selections ?? [], ctx));
          } else if (sub.name === 'pageInfo') {
            const info: Record<string, unknown> = {};
            for (const field of sub.selections ?? []) {
              if (field.name === 'hasNextPage') info[field.alias ?? field.name] = total > page.length;
              else if (field.name === 'endCursor') {
                info[field.alias ?? field.name] = page.length > 0 ? issueCursor(page[page.length - 1]?.number ?? 0) : null;
              }
            }
            conn[sub.alias ?? sub.name] = info;
          }
        }
        void nodes;
        void pageInfo;
        out[key] = conn;
        break;
      }
      case 'pullRequests': {
        const first = typeof args.first === 'number' ? args.first : undefined;
        let list = [...repo.pulls.values()].filter((pull) => pull.state === 'open');
        list.sort((a, b) => b.number - a.number);
        if (first !== undefined) list = list.slice(0, first);
        const conn: Record<string, unknown> = {};
        for (const sub of sel.selections ?? []) {
          if (sub.name === 'nodes') {
            conn[sub.alias ?? sub.name] = list.map((pull) => resolvePullFields(pull, repo, sub.selections ?? [], ctx));
          }
        }
        out[key] = conn;
        break;
      }
      case 'pullRequest': {
        const number = args.number as number | undefined;
        const pull = typeof number === 'number' ? repo.pulls.get(number) : undefined;
        out[key] = pull === undefined ? null : resolvePullFields(pull, repo, sel.selections ?? [], ctx);
        break;
      }
      default:
        ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "Repository".` });
        break;
    }
  }
  return out;
}

function resolveNode(id: string, selections: GqlSelection[], ctx: GqlContext, variables: Record<string, unknown>): Record<string, unknown> | null {
  const entry = globalIdRegistry.get(id);
  if (entry === undefined) return null;
  const repo = findRepo(entry.owner, entry.repo);
  if (repo === undefined) return null;
  if (entry.kind === 'repo') {
    const out: Record<string, unknown> = {};
    for (const sel of selections) {
      if (sel.fragmentType !== null && sel.fragmentType !== 'Repository') continue;
      if (sel.fragmentType !== null) {
        const frag = resolveRepositoryFields(repo, sel.selections ?? [], ctx, variables);
        Object.assign(out, frag);
        continue;
      }
      const single = resolveRepositoryFields(repo, [sel], ctx, variables);
      Object.assign(out, single);
    }
    out.id = repoGlobalId(repo);
    return out;
  }
  if (entry.kind === 'issue') {
    const issue = repo.issues.get(entry.number);
    if (issue === undefined) return null;
    const out: Record<string, unknown> = {};
    for (const sel of selections) {
      if (sel.fragmentType !== null && sel.fragmentType !== 'Issue') continue;
      if (sel.fragmentType !== null) {
        Object.assign(out, resolveIssueFields(issue, repo, sel.selections ?? [], ctx));
        continue;
      }
      Object.assign(out, resolveIssueFields(issue, repo, [sel], ctx));
    }
    out.id = issueGlobalId(repo, issue.number);
    return out;
  }
  if (entry.kind === 'pull') {
    const pull = repo.pulls.get(entry.number);
    if (pull === undefined) return null;
    const out: Record<string, unknown> = {};
    for (const sel of selections) {
      if (sel.fragmentType !== null && sel.fragmentType !== 'PullRequest') continue;
      if (sel.fragmentType !== null) {
        Object.assign(out, resolvePullFields(pull, repo, sel.selections ?? [], ctx));
        continue;
      }
      Object.assign(out, resolvePullFields(pull, repo, [sel], ctx));
    }
    out.id = pullGlobalId(repo, pull.number);
    return out;
  }
  return null;
}

function resolveTypeFields(typeName: string, selections: GqlSelection[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.name === 'fields') {
      const names = INTROSPECTION_FIELDS[typeName] ?? [];
      out[sel.alias ?? sel.name] = names.map((name) => ({ name }));
    } else if (sel.name === 'enumValues') {
      const names = typeName === 'SearchType' ? SEARCH_TYPE_ENUMS : [];
      out[sel.alias ?? sel.name] = names.map((name) => ({ name }));
    } else if (sel.name === 'name') {
      out[sel.alias ?? sel.name] = typeName;
    }
  }
  return out;
}

function executeOperation(op: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown> | null; errors: Array<{ message: string }> } {
  const ctx: GqlContext = { errors: [] };
  const data: Record<string, unknown> = {};
  if (op.kind === 'query') {
    for (const sel of op.fields) {
      const key = sel.alias ?? sel.name;
      const args = resolveVariables(sel.args, variables) as Record<string, unknown>;
      if (sel.name === 'viewer') {
        const viewer: Record<string, unknown> = {};
        for (const sub of sel.selections ?? []) {
          if (sub.name === 'login') viewer[sub.alias ?? sub.name] = VIEWER_LOGIN;
          else ctx.errors.push({ message: `Cannot query field "${sub.name}" on type "Viewer".` });
        }
        data[key] = viewer;
      } else if (sel.name === 'repository') {
        const owner = String(args.owner ?? '');
        const name = String(args.name ?? '');
        const repo = owner === VIEWER_LOGIN ? findRepo(owner, name) : undefined;
        data[key] = repo === undefined ? null : resolveRepositoryFields(repo, sel.selections ?? [], ctx, variables);
      } else if (sel.name === 'node') {
        const id = String(args.id ?? '');
        data[key] = resolveNode(id, sel.selections ?? [], ctx, variables);
      } else if (sel.name === '__type') {
        const typeName = String(args.name ?? '');
        if (!(typeName in INTROSPECTION_FIELDS) && typeName !== 'SearchType') data[key] = null;
        else data[key] = resolveTypeFields(typeName, sel.selections ?? []);
      } else {
        ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "Query".` });
      }
    }
    return { data, errors: ctx.errors };
  }
  // Mutations.
  for (const sel of op.fields) {
    const key = sel.alias ?? sel.name;
    const args = resolveVariables(sel.args, variables) as Record<string, unknown>;
    const input = isRecord(args.input) ? args.input : {};
    if (sel.name === 'createIssue') {
      const repoId = String(input.repositoryId ?? '');
      const entry = globalIdRegistry.get(repoId);
      const repo = entry !== undefined && entry.kind === 'repo' ? findRepo(entry.owner, entry.repo) : undefined;
      if (repo === undefined) {
        ctx.errors.push({ message: 'createIssue: unknown repositoryId' });
        data[key] = null;
        continue;
      }
      const issue = createIssueRecord(repo, String(input.title ?? ''), String(input.body ?? ''), []);
      const issueOut: Record<string, unknown> = {};
      for (const sub of (sel.selections ?? []).find((s) => s.name === 'issue')?.selections ?? []) {
        if (sub.name === 'number') issueOut[sub.alias ?? sub.name] = issue.number;
        else if (sub.name === 'id') issueOut[sub.alias ?? sub.name] = issueGlobalId(repo, issue.number);
      }
      data[key] = { issue: issueOut };
    } else if (sel.name === 'closeIssue') {
      const issueId = String(input.issueId ?? '');
      const entry = globalIdRegistry.get(issueId);
      const repo = entry !== undefined && entry.kind === 'issue' ? findRepo(entry.owner, entry.repo) : undefined;
      const issue = repo?.issues.get(entry?.number ?? -1);
      if (repo === undefined || issue === undefined) {
        ctx.errors.push({ message: 'closeIssue: unknown issueId' });
        data[key] = null;
        continue;
      }
      issue.state = 'closed';
      issue.jsonStr = issueJsonString(issue);
      const issueOut: Record<string, unknown> = {};
      for (const sub of (sel.selections ?? []).find((s) => s.name === 'issue')?.selections ?? []) {
        if (sub.name === 'number') issueOut[sub.alias ?? sub.name] = issue.number;
        else if (sub.name === 'id') issueOut[sub.alias ?? sub.name] = issueGlobalId(repo, issue.number);
        else if (sub.name === 'state') issueOut[sub.alias ?? sub.name] = 'CLOSED';
      }
      data[key] = { issue: issueOut };
    } else if (sel.name === 'createPullRequest') {
      const repoId = String(input.repositoryId ?? '');
      const entry = globalIdRegistry.get(repoId);
      const repo = entry !== undefined && entry.kind === 'repo' ? findRepo(entry.owner, entry.repo) : undefined;
      const headRef = String(input.headRefName ?? '');
      const baseRef = String(input.baseRefName ?? '');
      if (repo === undefined || !repo.refs.has(`refs/heads/${headRef}`) || !repo.refs.has(`refs/heads/${baseRef}`)) {
        ctx.errors.push({ message: 'createPullRequest: unknown repository or branch' });
        data[key] = null;
        continue;
      }
      const duplicate = [...repo.pulls.values()].find((pull) => pull.headRef === headRef && pull.state === 'open');
      if (duplicate !== undefined) {
        ctx.errors.push({ message: 'createPullRequest: a pull request already exists for this head branch' });
        data[key] = null;
        continue;
      }
      const pull = createPullRecord(repo, String(input.title ?? ''), String(input.body ?? ''), headRef, baseRef);
      const pullOut: Record<string, unknown> = {};
      for (const sub of (sel.selections ?? []).find((s) => s.name === 'pullRequest')?.selections ?? []) {
        if (sub.name === 'number') pullOut[sub.alias ?? sub.name] = pull.number;
        else if (sub.name === 'id') pullOut[sub.alias ?? sub.name] = pullGlobalId(repo, pull.number);
        else if (sub.name === 'state') pullOut[sub.alias ?? sub.name] = 'OPEN';
        else if (sub.name === 'headRefName') pullOut[sub.alias ?? sub.name] = pull.headRef;
        else if (sub.name === 'baseRefName') pullOut[sub.alias ?? sub.name] = pull.baseRef;
      }
      data[key] = { pullRequest: pullOut };
    } else if (sel.name === 'mergePullRequest') {
      const pullId = String(input.pullRequestId ?? '');
      const entry = globalIdRegistry.get(pullId);
      const repo = entry !== undefined && entry.kind === 'pull' ? findRepo(entry.owner, entry.repo) : undefined;
      const pull = repo?.pulls.get(entry?.number ?? -1);
      if (repo === undefined || pull === undefined) {
        ctx.errors.push({ message: 'mergePullRequest: unknown pullRequestId' });
        data[key] = null;
        continue;
      }
      const outcome = squashMerge(repo, pull, `Merge pull request #${pull.number} from ${pull.headRef}`);
      if (outcome.ok && outcome.commitSha !== null) {
        pull.state = 'closed';
        pull.merged = true;
        pull.mergedAt = FIXED_ISO;
        pull.mergeSha = outcome.commitSha;
        pull.jsonStr = pullJsonString(pull);
      }
      const pullOut: Record<string, unknown> = {};
      for (const sub of (sel.selections ?? []).find((s) => s.name === 'pullRequest')?.selections ?? []) {
        if (sub.name === 'number') pullOut[sub.alias ?? sub.name] = pull.number;
        else if (sub.name === 'merged') pullOut[sub.alias ?? sub.name] = pull.merged;
        else if (sub.name === 'state') pullOut[sub.alias ?? sub.name] = pullStateGql(pull);
        else if (sub.name === 'id') pullOut[sub.alias ?? sub.name] = pullGlobalId(repo, pull.number);
      }
      data[key] = { pullRequest: pullOut };
    } else if (sel.name === 'addComment') {
      const subjectId = String(input.subjectId ?? '');
      const entry = globalIdRegistry.get(subjectId);
      const repo = entry !== undefined && entry.kind === 'issue' ? findRepo(entry.owner, entry.repo) : undefined;
      const issue = repo?.issues.get(entry?.number ?? -1);
      if (repo === undefined || issue === undefined) {
        ctx.errors.push({ message: 'addComment: unknown subjectId' });
        data[key] = null;
        continue;
      }
      const comment = { id: nextGlobalCommentId, body: String(input.body ?? '') };
      nextGlobalCommentId += 1;
      issue.comments.push(comment);
      globalIdRegistry.set(commentGlobalId(repo, issue.number, comment.id), { kind: 'comment', owner: repo.owner, repo: repo.name, number: issue.number });
      const nodeOut: Record<string, unknown> = {};
      const edgeSel = (sel.selections ?? []).find((s) => s.name === 'commentEdge');
      const nodeSel = edgeSel?.selections?.find((s) => s.name === 'node');
      for (const sub of nodeSel?.selections ?? []) {
        if (sub.name === 'id') nodeOut[sub.alias ?? sub.name] = commentGlobalId(repo, issue.number, comment.id);
        else if (sub.name === 'body') nodeOut[sub.alias ?? sub.name] = comment.body;
      }
      data[key] = { commentEdge: { node: nodeOut } };
    } else {
      ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "Mutation".` });
    }
  }
  return { data, errors: ctx.errors };
}

async function handleGraphQL(req: http.IncomingMessage, res: HttpRes): Promise<void> {
  if (!checkAuth(req)) {
    sendError(res, 401, 'Requires authentication');
    return;
  }
  if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
    sendError(res, 404, 'Not Found');
    return;
  }
  const body = await readBody(req);
  let payload: unknown;
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    sendError(res, 400, 'Problems parsing JSON');
    return;
  }
  const runOne = (doc: unknown): Record<string, unknown> => {
    if (!isRecord(doc) || typeof doc.query !== 'string') {
      return { errors: [{ message: 'GraphQL request must carry a query string' }] };
    }
    const variables = isRecord(doc.variables) ? (doc.variables as Record<string, unknown>) : {};
    let ops: GqlOperation[];
    try {
      ops = new GqlParser(tokenizeGql(doc.query)).parseDocument();
    } catch (err) {
      return { data: null, errors: [{ message: err instanceof Error ? err.message : 'GraphQL parse error' }] };
    }
    let op: GqlOperation | undefined;
    if (typeof doc.operationName === 'string' && doc.operationName !== '') {
      op = ops.find((entry) => entry.name === doc.operationName);
    }
    if (op === undefined) op = ops[0];
    if (op === undefined) return { data: null, errors: [{ message: 'No operation in GraphQL document' }] };
    const result = executeOperation(op, variables);
    if (result.errors.length > 0) return { data: result.data, errors: result.errors };
    return { data: result.data };
  };
  if (Array.isArray(payload)) {
    sendJson(res, 200, payload.map(runOne));
    return;
  }
  sendJson(res, 200, runOne(payload));
}

// -------------------------------------------------------------------------------------------
// MCP (Model Context Protocol) — modern 2026-07-28 server/discover plus the legacy handshake
// -------------------------------------------------------------------------------------------

const MCP_REVISION = '2026-07-28';
const MCP_SUPPORTED = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

// Built once: two tools/list answers must be byte-identical.
const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the viewer.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
        owner: { type: 'string', description: 'Owner login (defaults to the viewer)' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Read one repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository, optionally filtered by state.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Squash-merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpOk(res: HttpRes, id: unknown, result: unknown): void {
  sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, result });
}

function mcpError(res: HttpRes, status: number, id: unknown, code: number, message: string): void {
  sendJson(res, status, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

function mcpToolOk(value: unknown): Record<string, unknown> {
  const text = JSON.stringify(value);
  return { content: [{ type: 'text', text }], structuredContent: value, isError: false };
}

function mcpToolFail(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function mcpRepoObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: repoKey(repo.owner, repo.name),
    owner: { login: repo.owner },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
  };
}

async function handleMcp(req: http.IncomingMessage, res: HttpRes): Promise<void> {
  if ((req.method ?? 'GET').toUpperCase() !== 'POST') {
    sendError(res, 404, 'Not Found');
    return;
  }
  const raw = await readBody(req);
  const text = raw.toString('utf8');
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    // Parse error: HTTP 400, JSON-RPC -32700. Recover the request id when it is legible.
    let id: unknown = null;
    const match = /"id"\s*:\s*("[^"]*"|-?\d+)/.exec(text);
    if (match !== null) {
      const rawId = match[1] as string;
      id = rawId.startsWith('"') ? rawId.slice(1, -1) : Number(rawId);
    }
    mcpError(res, 400, id, -32700, 'Parse error');
    return;
  }
  if (!isRecord(payload) || typeof payload.method !== 'string') {
    mcpError(res, 400, isRecord(payload) ? payload.id ?? null : null, -32600, 'Invalid Request');
    return;
  }
  const id = payload.id ?? null;
  const isNotification = payload.id === undefined;
  if (!checkAuth(req)) {
    if (isNotification) {
      res.writeHead(401);
      res.end();
      return;
    }
    mcpError(res, 401, id, -32000, 'Requires authentication');
    return;
  }
  const method = payload.method;
  const params = isRecord(payload.params) ? payload.params : {};

  if (method === 'server/discover') {
    mcpOk(res, id, {
      supportedVersions: MCP_SUPPORTED,
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
      _meta: {
        'io.modelcontextprotocol/serverInfo': { name: FORGE_NAME, version: FORGE_VERSION },
        'io.modelcontextprotocol/protocolVersion': MCP_REVISION,
      },
    });
    return;
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const negotiated = MCP_SUPPORTED.includes(offered) ? offered : MCP_REVISION;
    mcpOk(res, id, {
      protocolVersion: negotiated,
      capabilities: { tools: {} },
      serverInfo: { name: FORGE_NAME, version: FORGE_VERSION },
    });
    return;
  }
  if (method === 'notifications/initialized' || method.startsWith('notifications/')) {
    res.writeHead(202);
    res.end();
    return;
  }
  if (method === 'ping') {
    mcpOk(res, id, {});
    return;
  }
  if (method === 'tools/list') {
    mcpOk(res, id, { tools: MCP_TOOLS });
    return;
  }
  if (method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = isRecord(params.arguments) ? params.arguments : {};
    const tool = MCP_TOOLS.find((entry) => entry.name === name);
    if (tool === undefined) {
      mcpError(res, 200, id, -32602, `Unknown tool: ${name}`);
      return;
    }
    const required = Array.isArray(tool.inputSchema.required) ? (tool.inputSchema.required as string[]) : [];
    const missing = required.filter((key) => args[key] === undefined || args[key] === null || args[key] === '');
    if (missing.length > 0) {
      mcpError(res, 200, id, -32602, `Missing required arguments: ${missing.join(', ')}`);
      return;
    }
    const owner = typeof args.owner === 'string' ? args.owner : VIEWER_LOGIN;
    const repoName = typeof args.repo === 'string' ? args.repo : typeof args.name === 'string' ? args.name : '';
    if (name === 'create_repo') {
      if (findRepo(VIEWER_LOGIN, repoName) !== undefined) {
        mcpOk(res, id, mcpToolFail('Repository already exists'));
        return;
      }
      const repo = createRepoRecord(VIEWER_LOGIN, repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
      mcpOk(res, id, mcpToolOk(mcpRepoObject(repo)));
      return;
    }
    if (owner !== VIEWER_LOGIN) {
      mcpOk(res, id, mcpToolFail('Repository not found'));
      return;
    }
    const repo = findRepo(owner, repoName);
    if (repo === undefined) {
      mcpOk(res, id, mcpToolFail('Repository not found'));
      return;
    }
    if (name === 'get_repo') {
      mcpOk(res, id, mcpToolOk(mcpRepoObject(repo)));
      return;
    }
    if (name === 'create_issue') {
      const issue = createIssueRecord(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', []);
      mcpOk(res, id, mcpToolOk(issueJsonObject(issue)));
      return;
    }
    if (name === 'list_issues') {
      const state = typeof args.state === 'string' ? args.state.toLowerCase() : 'open';
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((issue) => issue.state === 'open');
      else if (state === 'closed') list = list.filter((issue) => issue.state === 'closed');
      list.sort((a, b) => b.createdSeq - a.createdSeq);
      mcpOk(res, id, mcpToolOk(list.map((issue) => issueJsonObject(issue))));
      return;
    }
    if (name === 'create_pull_request') {
      const head = String(args.head ?? '');
      const base = String(args.base ?? '');
      if (!repo.refs.has(`refs/heads/${head}`) || !repo.refs.has(`refs/heads/${base}`)) {
        mcpOk(res, id, mcpToolFail('Head or base branch does not exist'));
        return;
      }
      const duplicate = [...repo.pulls.values()].find((pull) => pull.headRef === head && pull.state === 'open');
      if (duplicate !== undefined) {
        mcpOk(res, id, mcpToolFail('A pull request already exists for this head branch'));
        return;
      }
      const pull = createPullRecord(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', head, base);
      mcpOk(res, id, mcpToolOk(pullJsonObject(pull)));
      return;
    }
    if (name === 'merge_pull_request') {
      const number = Number(args.pull_number);
      const pull = repo.pulls.get(number);
      if (pull === undefined) {
        mcpOk(res, id, mcpToolFail('Pull request not found'));
        return;
      }
      if (pull.state === 'closed') {
        mcpOk(res, id, mcpToolFail('Pull request is already closed'));
        return;
      }
      const outcome = squashMerge(repo, pull, `Merge pull request #${pull.number} from ${pull.headRef}`);
      if (!outcome.ok || outcome.commitSha === null) {
        mcpOk(res, id, mcpToolFail('Merge conflict'));
        return;
      }
      pull.state = 'closed';
      pull.merged = true;
      pull.mergedAt = FIXED_ISO;
      pull.mergeSha = outcome.commitSha;
      pull.jsonStr = pullJsonString(pull);
      mcpOk(res, id, mcpToolOk({ merged: true, number: pull.number, state: 'closed', sha: outcome.commitSha }));
      return;
    }
    mcpError(res, 200, id, -32602, `Unknown tool: ${name}`);
    return;
  }
  mcpError(res, 200, id, -32601, `Method not found: ${method}`);
}

// -------------------------------------------------------------------------------------------
// Dispatcher, server, trial lifecycle
// -------------------------------------------------------------------------------------------

async function handleGitInfoRefs(req: http.IncomingMessage, res: HttpRes, owner: string, repoName: string, query: URLSearchParams): Promise<void> {
  const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
  if (repo === undefined) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const service = query.get('service');
  const proto = req.headers['git-protocol'];
  if (service === 'git-receive-pack') {
    sendRaw(res, 200, 'application/x-git-receive-pack-advertisement', v0Advertisement(repo, 'git-receive-pack'));
    return;
  }
  if (proto === 'version=2') {
    sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement(repo));
    return;
  }
  if (service === 'git-upload-pack') {
    sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', v0Advertisement(repo, 'git-upload-pack'));
    return;
  }
  sendRaw(res, 200, 'application/x-git-upload-pack-advertisement', v2Advertisement(repo));
}

async function handleGitPost(req: http.IncomingMessage, res: HttpRes, owner: string, repoName: string, service: 'git-upload-pack' | 'git-receive-pack'): Promise<void> {
  const repo = owner === VIEWER_LOGIN ? findRepo(owner, repoName) : undefined;
  if (repo === undefined) {
    sendError(res, 404, 'Not Found');
    return;
  }
  const body = await readBody(req);
  try {
    if (service === 'git-upload-pack') {
      const out = handleUploadPack(repo, body);
      sendRaw(res, out.status, out.contentType, out.body);
    } else {
      const out = handleReceivePack(repo, body);
      sendRaw(res, out.status, out.contentType, out.body);
    }
  } catch (err) {
    // A malformed git request must never kill the server (repo-survives-errors).
    process.stderr.write(`git ${service} error: ${err instanceof Error ? err.message : String(err)}\n`);
    sendError(res, 400, 'Bad git request');
  }
}

async function dispatch(req: http.IncomingMessage, res: HttpRes): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  const path = url.pathname;
  if (req.method === 'GET' && path === '/healthz') {
    sendJson(res, 200, { ok: true });
    return;
  }
  if (path === '/api/graphql') {
    await handleGraphQL(req, res);
    return;
  }
  if (path === '/mcp') {
    await handleMcp(req, res);
    return;
  }
  if (path === '/api/v3' || path.startsWith('/api/v3/')) {
    const rest = path === '/api/v3' ? [] : path.slice('/api/v3/'.length).split('/').filter((segment) => segment !== '');
    await handleRest(req, res, rest, url.searchParams);
    return;
  }
  const gitMatch = /^\/([^/]+)\/([^/]+)\.git\/(info\/refs|git-upload-pack|git-receive-pack)$/.exec(path);
  if (gitMatch !== null) {
    const [, owner, repoName, tail] = gitMatch as unknown as [string, string, string, string];
    if (tail === 'info/refs' && req.method === 'GET') {
      await handleGitInfoRefs(req, res, owner, repoName, url.searchParams);
      return;
    }
    if (tail === 'git-upload-pack' && req.method === 'POST') {
      await handleGitPost(req, res, owner, repoName, 'git-upload-pack');
      return;
    }
    if (tail === 'git-receive-pack' && req.method === 'POST') {
      await handleGitPost(req, res, owner, repoName, 'git-receive-pack');
      return;
    }
  }
  sendError(res, 404, 'Not Found');
}

const server = http.createServer((req, res) => {
  dispatch(req, res).catch((err) => {
    process.stderr.write(`dispatch error: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
    if (!res.headersSent) sendError(res, 500, 'Internal error');
    else res.end();
  });
});

process.on('uncaughtException', (err) => {
  process.stderr.write(`uncaught: ${err.stack ?? err.message}\n`);
});

async function registerAndWait(port: number): Promise<void> {
  if (ENV_URL === '') return; // standalone: serve until killed
  try {
    await fetch(`${ENV_URL}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ port }),
    });
  } catch (err) {
    process.stderr.write(`register failed: ${err instanceof Error ? err.message : String(err)}\n`);
  }
  let delay = 250;
  for (;;) {
    await sleep(delay);
    delay = Math.min(delay * 2, 2000);
    try {
      const response = await fetch(`${ENV_URL}/done`);
      const data = (await response.json()) as { done?: boolean };
      if (data !== null && data.done === true) break;
    } catch {
      // keep polling
    }
  }
  process.exit(0);
}

server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  process.stderr.write(`github-core-clone listening on 127.0.0.1:${port}\n`);
  void registerAndWait(port);
});

process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
