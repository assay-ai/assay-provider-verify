// Minimal RFC 8941 parser: dictionaries whose members are inner lists of
// strings, integers, quoted strings, tokens or byte sequences, with parameters.
// Only what the Assay signature headers need.

export type Bare = string | number | { bytes: string }; // bytes = base64 text
export interface Member {
  /** String items of an inner list, when the member is an inner list. */
  list?: string[];
  /** Single item value, when the member is not an inner list. */
  item?: Bare;
  params: Map<string, Bare | true>;
  /** Raw text of the member after `name=` (inner list or item plus params). */
  raw: string;
}

export class ParseError extends Error {}

class Cursor {
  i = 0;
  constructor(readonly s: string) {}
  peek(): string | undefined { return this.s[this.i]; }
  eof(): boolean { return this.i >= this.s.length; }
  skipOws(): void { while (this.s[this.i] === " " || this.s[this.i] === "\t") this.i++; }
  skipSp(): void { while (this.s[this.i] === " ") this.i++; }
}

function parseKey(c: Cursor): string {
  const start = c.i;
  const first = c.peek();
  if (first === undefined || !/[a-z*]/.test(first)) throw new ParseError("bad key");
  while (!c.eof() && /[a-z0-9_\-.*]/.test(c.peek()!)) c.i++;
  return c.s.slice(start, c.i);
}

function parseBare(c: Cursor): Bare {
  const ch = c.peek();
  if (ch === '"') {
    c.i++;
    let out = "";
    for (;;) {
      const x = c.s[c.i++];
      if (x === undefined) throw new ParseError("unterminated string");
      if (x === '"') return out;
      if (x === "\\") {
        const n = c.s[c.i++];
        if (n !== '"' && n !== "\\") throw new ParseError("bad escape");
        out += n;
      } else {
        const code = x.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) throw new ParseError("bad char");
        out += x;
      }
    }
  }
  if (ch === ":") {
    c.i++;
    const end = c.s.indexOf(":", c.i);
    if (end < 0) throw new ParseError("unterminated bytes");
    const b64 = c.s.slice(c.i, end);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new ParseError("bad base64");
    c.i = end + 1;
    return { bytes: b64 };
  }
  if (ch !== undefined && /[-0-9]/.test(ch)) {
    const m = /^-?[0-9]{1,15}/.exec(c.s.slice(c.i));
    if (!m) throw new ParseError("bad integer");
    c.i += m[0].length;
    if (c.peek() === ".") throw new ParseError("decimals unsupported");
    return Number(m[0]);
  }
  if (ch !== undefined && /[A-Za-z*]/.test(ch)) {
    const start = c.i;
    while (!c.eof() && /[A-Za-z0-9!#$%&'*+\-.^_`|~:/]/.test(c.peek()!)) c.i++;
    return c.s.slice(start, c.i);
  }
  throw new ParseError("bad item");
}

function parseParams(c: Cursor): Map<string, Bare | true> {
  const params = new Map<string, Bare | true>();
  while (c.peek() === ";") {
    c.i++;
    c.skipSp();
    const key = parseKey(c);
    let value: Bare | true = true;
    if (c.peek() === "=") {
      c.i++;
      value = parseBare(c);
    }
    params.set(key, value);
  }
  return params;
}

/** Parse a dictionary header value into its members (insertion ordered). */
export function parseDictionary(input: string): Map<string, Member> {
  const c = new Cursor(input);
  const out = new Map<string, Member>();
  c.skipOws();
  while (!c.eof()) {
    const key = parseKey(c);
    let member: Member;
    if (c.peek() === "=") {
      c.i++;
      const start = c.i;
      if (c.peek() === "(") {
        c.i++;
        const list: string[] = [];
        for (;;) {
          c.skipSp();
          if (c.peek() === ")") { c.i++; break; }
          const v = parseBare(c);
          if (typeof v !== "string") throw new ParseError("inner list items must be strings");
          list.push(v);
          const n = c.peek();
          if (n !== " " && n !== ")") throw new ParseError("bad inner list");
        }
        const params = parseParams(c);
        member = { list, params, raw: c.s.slice(start, c.i) };
      } else {
        const item = parseBare(c);
        const params = parseParams(c);
        member = { item, params, raw: c.s.slice(start, c.i) };
      }
    } else {
      member = { item: "true", params: parseParams(c), raw: "" };
    }
    out.set(key, member);
    c.skipOws();
    if (c.eof()) break;
    if (c.peek() !== ",") throw new ParseError("expected comma");
    c.i++;
    c.skipOws();
    if (c.eof()) throw new ParseError("trailing comma");
  }
  return out;
}
