// The test probe of tests/worker/config.capnp: one loopback endpoint the
// tests call with JSON {target, fn, args}. "helper" calls an exported pure
// function of worker/intake.js (an allowlist, below), "constants" returns
// its INTAKE table, "cause" calls sendCause on a thrown value it builds
// from a JSON description, "limiter" calls a method of the IntakeLimiter
// Durable Object with an injected time, "capture" and "burst" reach the
// emulated bindings. BrokenLimiter is the limiter of the intake-broken-limiter
// service: every call throws, so the Worker must fail closed.

import { DurableObject } from "cloudflare:workers";
import * as intake from "./intake.js";

const HELPERS = new Set([
  "clientKeyMaterial", "detectImageType", "normalizeText", "isBlank", "defangSchemes",
  "subjectFor", "limiterDecide", "dayKey", "cleanSubject", "isValidEmail", "pageUrlOk", "recipientOf",
]);
const LIMITER_METHODS = new Set(["attempt", "reserve", "refund", "purge", "rows", "noticeFailed", "noticeSent"]);
const CAPTURE_METHODS = new Set(["list", "clear", "setFail", "send", "verdict"]);
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

// The value a failed send() throws, from a JSON description (the sendCause
// table of test_intake.py): kind "Error", "TypeError", "string" (the
// message itself is thrown) or "null"; for an error, an own `code` and
// `name` when given, or a `code` getter that throws (codeThrows).
function thrownValue(desc) {
  if (desc.kind === "null") return null;
  if (desc.kind === "string") return desc.message;
  const error = desc.kind === "TypeError" ? new TypeError(desc.message || "") : new Error(desc.message || "");
  if (Object.hasOwn(desc, "code")) error.code = desc.code;
  if (Object.hasOwn(desc, "name")) error.name = desc.name;
  if (desc.codeThrows) Object.defineProperty(error, "code", { get() { throw new Error("code getter"); } });
  return error;
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

async function call(env, { target, fn, args = [] }) {
  if (target === "constants") return intake.INTAKE;
  if (target === "cause") return intake.sendCause(thrownValue(args[0]));
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
  const pending = [];
  const ctx = { waitUntil: (promise) => {
    passed.push(promise);
    // Still unsettled one microtask turn after the call: the running notice, not a stand-in.
    const mark = { settled: false, turn: false };
    promise.then(() => { mark.settled = !mark.turn; });
    Promise.resolve().then(() => { mark.turn = true; });
    pending.push(mark);
    // Fix round 7: the order of the notice's send completing and this
    // promise settling, so a stand-in that settles later than one microtask
    // turn but before the send is caught too.
    promise.then(() => { order.push("settled"); });
  } };
  const order = [];
  const email = { send: async (message) => {
    try {
      return await env.CAPTURE.send(message);
    } finally {
      order.push("sent");
    }
  } };
  const forwarded = new Request("https://intake.interviewscam.com/submit",
    { method: "POST", headers: request.headers, body: request.body });
  // Fix round 8: the limiter as the Worker sees it, forwarded whole, with
  // only the two notice reports wrapped to record when one is done, so a
  // promise that covers the send but not its report fails the order check.
  // Fix round 9: noticeFailed too, and "sent" is pushed whatever the send's
  // outcome, so the failure branch is held to the same order.
  const recordingStub = (stub) => new Proxy(stub, { get(target, prop) {
    if (prop !== "noticeSent" && prop !== "noticeFailed") return target[prop];
    return async (...args) => {
      const result = await target[prop](...args);
      order.push("recorded");
      return result;
    };
  } });
  const limiter = new Proxy(env.RECORD, { get(target, prop) {
    if (prop === "get") return (...args) => recordingStub(target.get(...args));
    const value = target[prop];
    return typeof value === "function" ? value.bind(target) : value;
  } });
  const testEnv = { EMAIL: email, RATE_LIMITER: env.BURST, LIMITER: limiter,
    LIMITER_KEY: "f17474ac183f5727b19cad79d6bcc87ce754d404e1b5ffaf7ff3f83346bf0246",
    EMAIL_TO: "operator@example.com" };
  const response = await intake.default.fetch(forwarded, testEnv, ctx);
  // The response waits for the notice task on purpose: the refusal's log
  // code, E_NOTICE or E_DAILY_CAP, depends on its outcome (worker/intake.js,
  // "const cause = await task", null when the notice went out; ADR-0006
  // Numbers, "Global cap": "the refusal logs code=E_NOTICE").
  order.push("returned");
  const settled = await Promise.all(passed);
  return { status: response.status, location: response.headers.get("Location"), waited: passed.length, settled,
    pending: pending.map((mark) => !mark.settled), order };
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
