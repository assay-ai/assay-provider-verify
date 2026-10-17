import { readFileSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import express from "express";
import Fastify from "fastify";
import { Hono } from "hono";
import { assayVerify as expressVerify } from "../src/express.js";
import { assayVerifyPlugin } from "../src/fastify.js";
import { assayVerify as honoVerify } from "../src/hono.js";
import { withAssayVerify } from "../src/next.js";
import { redisReplayStore } from "../src/redis.js";
import type { VerifyOptions } from "../src/index.js";

const v1 = JSON.parse(readFileSync(new URL("../../test-vectors/v1.json", import.meta.url), "utf8"));
const c = v1.cases[0];
const u = new URL(c.request.url);
const path = u.pathname + u.search;
const opts: VerifyOptions = { jwks: { keys: [v1.publicKeyJwk] }, now: () => c.params.created, authority: "api.example.test" };
const REJECT = '{"error":"invalid_assay_signature","reason":"DIGEST_MISMATCH"}';

const closers: Array<() => Promise<unknown>> = [];
afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      closers.push(() => new Promise((r) => server.close(r)));
      resolve((server.address() as AddressInfo).port);
    });
  });
}

/** Bridge a fetch-style handler (Hono, Next) to node:http. */
function fetchServer(handler: (req: Request) => Promise<Response>): Server {
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    for await (const ch of req) chunks.push(ch as Buffer);
    const body = Buffer.concat(chunks);
    const hasBody = body.length > 0 || req.headers["content-length"] !== undefined;
    const r = new Request(`http://${req.headers.host}${req.url}`, {
      method: req.method,
      headers: req.headers as Record<string, string>,
      body: hasBody ? body : undefined,
    });
    const out = await handler(r);
    res.statusCode = out.status;
    out.headers.forEach((v, k) => res.setHeader(k, v));
    res.end(Buffer.from(await out.arrayBuffer()));
  });
}

async function send(port: number, tamper = false, extra: Record<string, string> = {}) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`, {
    method: c.request.method,
    headers: { ...c.request.headers, ...c.expected.headers, "content-type": "application/json", ...extra },
    body: tamper ? '{"q":"x y"}' : c.request.body,
  });
  return { status: res.status, ct: res.headers.get("content-type"), text: await res.text() };
}

function suite(name: string, start: (o: VerifyOptions) => Promise<number>) {
  describe(name, () => {
    it("accepts a valid request and the handler sees the JSON body", async () => {
      const port = await start(opts);
      const r = await send(port);
      expect(r.status).toBe(200);
      expect(JSON.parse(r.text)).toEqual({ q: "a b" });
    });
    it("rejects a tampered body", async () => {
      const port = await start(opts);
      const r = await send(port, true);
      expect(r.status).toBe(401);
      expect(r.ct).toContain("application/json");
      expect(r.text).toBe(REJECT);
    });
  });
}

suite("express", async (o) => {
  const app = express();
  app.use(expressVerify(o));
  app.post("/v1/search", (req, res) => {
    expect(Buffer.isBuffer((req as unknown as { rawBody: Buffer }).rawBody)).toBe(true);
    res.json(req.body);
  });
  return listen(createServer(app));
});

suite("fastify", async (o) => {
  const app = Fastify();
  await app.register(assayVerifyPlugin, o);
  app.post("/v1/search", async (req) => req.body);
  await app.listen({ port: 0, host: "127.0.0.1" });
  closers.push(() => app.close());
  return (app.server.address() as AddressInfo).port;
});

suite("hono", async (o) => {
  const app = new Hono();
  app.use("*", honoVerify(o) as never);
  app.post("/v1/search", async (ctx) => ctx.json(await ctx.req.json()));
  return listen(fetchServer((r) => Promise.resolve(app.fetch(r))));
});

suite("next", async (o) => {
  const handler = withAssayVerify(async (req) => Response.json(await req.json()), o);
  return listen(fetchServer(handler));
});

describe("authority option", () => {
  it("passes behind a Host rewrite, fails without it", async () => {
    const app = express();
    app.use(expressVerify({ ...opts }));
    app.post("/v1/search", (req, res) => res.json(req.body));
    const port = await listen(createServer(app));
    const status = await new Promise<number>((resolve, reject) => {
      {
        const r = request({ host: "127.0.0.1", port, path, method: "POST", headers: { ...c.request.headers, ...c.expected.headers, "content-type": "application/json", host: "localhost:1234" } }, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        r.on("error", reject);
        r.end(c.request.body);
      }
    });
    expect(status).toBe(200);

    const app2 = express();
    app2.use(expressVerify({ ...opts, authority: undefined }));
    app2.post("/v1/search", (req, res) => res.json(req.body));
    const port2 = await listen(createServer(app2));
    const r2 = await send(port2);
    expect(r2.status).toBe(401);
    expect(r2.text).toBe('{"error":"invalid_assay_signature","reason":"BAD_SIGNATURE"}');
  });
});

describe("express misconfiguration", () => {
  it("returns 500 when a body parser ran first", async () => {
    const app = express();
    app.use(express.json());
    app.use(expressVerify(opts));
    app.post("/v1/search", (req, res) => res.json(req.body));
    const r = await send(await listen(createServer(app)));
    expect(r.status).toBe(500);
    expect(r.text).toContain("mount assayVerify() before body parsers");
  });
});

describe("redisReplayStore", () => {
  it("node-redis style: second identical nonce is a replay", async () => {
    const seen = new Set<string>();
    const client = {
      isOpen: true,
      async set(k: string, _v: string, o: { NX: boolean; EX: number }) {
        expect(o).toEqual({ NX: true, EX: 305 });
        if (seen.has(k)) return null;
        seen.add(k);
        return "OK";
      },
    };
    const s = redisReplayStore(client);
    expect(await s.checkAndStore("n1", 305)).toBe(true);
    expect(await s.checkAndStore("n1", 305)).toBe(false);
    expect([...seen]).toEqual(["assay:nonce:n1"]);
  });
  it("ioredis style", async () => {
    const seen = new Set<string>();
    const client = {
      status: "ready",
      pipeline() {},
      async set(k: string, _v: string, ex: string, s: number, nx: string) {
        expect([ex, s, nx]).toEqual(["EX", 10, "NX"]);
        if (seen.has(k)) return null;
        seen.add(k);
        return "OK";
      },
    };
    const s = redisReplayStore(client, "p:");
    expect(await s.checkAndStore("n", 10)).toBe(true);
    expect(await s.checkAndStore("n", 10)).toBe(false);
    expect([...seen]).toEqual(["p:n"]);
  });
});
