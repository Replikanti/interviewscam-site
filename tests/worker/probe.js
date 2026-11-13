// The test probe of tests/worker/config.capnp: one loopback endpoint the
// tests call with JSON {target, fn, args}. "helper" calls an exported pure
// function of worker/intake.js (an allowlist, below), "constants" returns
// its INTAKE table, "limiter" calls a method of the IntakeLimiter Durable
// Object with an injected time, "capture" and "burst" reach the emulated
// bindings. BrokenLimiter is the limiter of the intake-broken-limiter
// service: every call throws, so the Worker must fail closed.

import { DurableObject } from "cloudflare:workers";
import * as intake from "./intake.js";

const HELPERS = new Set([
  "clientKeyMaterial", "detectImageType", "normalizeText", "isBlank", "defangSchemes",
  "subjectFor", "limiterDecide", "dayKey", "cleanSubject", "isValidEmail", "pageUrlOk",
]);
const LIMITER_METHODS = new Set(["attempt", "reserve", "refund", "purge", "rows", "noticeFailed", "noticeSent"]);
const CAPTURE_METHODS = new Set(["list", "clear", "setFail", "send"]);
const BURST_METHODS = new Set(["reset", "keys"]);
// The name of the one IntakeLimiter instance (LIMITER_NAME in intake.js,
// which a Worker's main module cannot export: its named exports must be
// handlers or classes). A different name here would address another
// instance, and every case that reads the limiter's rows would fail.
const LIMITER_NAME = "intake";

export class BrokenLimiter extends DurableObject {
  attempt() { throw new Error("broken limiter"); }
  reserve() { throw new Error("broken limiter"); }
  refund() { throw new Error("broken limiter"); }
}

// Counts nothing and admits every attempt, then throws on reserve(): the
// Worker must fail closed there too (intake-broken-reserve).
export class BrokenReserveLimiter extends DurableObject {
  attempt() { return { ok: true }; }
  reserve() { throw new Error("broken reserve"); }
  refund() { throw new Error("broken reserve"); }
}

// The limiter of intake-record: it records each call and the time or day
// the Worker passed, and can be told to answer "paused" or to throw, so the
// cases can see which time reserve() got (the fresh one, after the body),
// which day refund() and noticeFailed() name, and that an attempt() failure
// fails closed even when reserve() would work.
let recorded = [];
let recordMode = { paused: false, attemptThrows: false, refundThrows: false };

export class RecordingLimiter extends DurableObject {
  attempt(key, now) {
    recorded.push(["attempt", now]);
    if (recordMode.attemptThrows) throw new Error("attempt down");
    return { ok: true };
  }

  reserve(key, now) {
    recorded.push(["reserve", now]);
    if (recordMode.paused) return { ok: false, reason: "paused", notice: true, day: "2000-01-01", noticeTry: 51 };
    return { ok: true, day: "2000-01-01" };
  }

  refund(key, day) {
    recorded.push(["refund", day]);
    if (recordMode.refundThrows) throw new Error("refund down");
    return { ok: true };
  }

  noticeFailed(day) {
    recorded.push(["noticeFailed", day]);
    if (recordMode.refundThrows) throw new Error("reopen down");
    return { ok: true };
  }

  noticeSent(day) {
    recorded.push(["noticeSent", day]);
    if (recordMode.refundThrows) throw new Error("sent down");
    return { ok: true };
  }

  times() {
    return recorded;
  }

  setup(paused, attemptThrows, refundThrows) {
    recordMode = { paused: !!paused, attemptThrows: !!attemptThrows, refundThrows: !!refundThrows };
    recorded = [];
    return true;
  }
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

async function call(env, { target, fn, args = [] }) {
  if (target === "constants") return intake.INTAKE;
  if (target === "helper" && HELPERS.has(fn)) {
    if (fn === "detectImageType") return intake.detectImageType(fromHex(args[0]));
    return intake[fn](...args);
  }
  if (target === "limiter" && LIMITER_METHODS.has(fn)) {
    const stub = env.LIMITER.get(env.LIMITER.idFromName(LIMITER_NAME));
    return await stub[fn](...args);
  }
  if (target === "record") {
    const stub = env.RECORD.get(env.RECORD.idFromName("r"));
    return fn === "setup" ? await stub.setup(...args) : await stub.times();
  }
  if (target === "capture" && CAPTURE_METHODS.has(fn)) return await env.CAPTURE[fn](...args);
  if (target === "burst" && BURST_METHODS.has(fn)) return await env.BURST[fn](...args);
  throw new Error(`probe: unknown call ${target}.${fn}`);
}

// POST /waituntil: the Worker's fetch with a recording ctx and the
// recording limiter, so a case can see that the pause notice runs under
// ctx.waitUntil (fix round 5 of PR 2).
async function waitUntilCase(request, env) {
  const passed = [];
  const ctx = { waitUntil: (promise) => { passed.push(promise); } };
  const forwarded = new Request("https://intake.interviewscam.com/submit",
    { method: "POST", headers: request.headers, body: request.body });
  const testEnv = { EMAIL: env.CAPTURE, RATE_LIMITER: env.BURST, LIMITER: env.RECORD,
    LIMITER_KEY: "f17474ac183f5727b19cad79d6bcc87ce754d404e1b5ffaf7ff3f83346bf0246" };
  const response = await intake.default.fetch(forwarded, testEnv, ctx);
  const settled = await Promise.all(passed);
  return { status: response.status, location: response.headers.get("Location"), waited: passed.length, settled };
}

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname === "/waituntil") {
      return Response.json({ ok: true, result: await waitUntilCase(request, env) });
    }
    try {
      const result = await call(env, await request.json());
      return Response.json({ ok: true, result: result === undefined ? null : result });
    } catch (error) {
      return Response.json({ ok: false, error: String(error && error.message || error) });
    }
  },
};
