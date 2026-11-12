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
const LIMITER_METHODS = new Set(["attempt", "reserve", "refund", "purge", "rows"]);
const CAPTURE_METHODS = new Set(["list", "clear", "setFail"]);
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
  if (target === "capture" && CAPTURE_METHODS.has(fn)) return await env.CAPTURE[fn](...args);
  if (target === "burst" && BURST_METHODS.has(fn)) return await env.BURST[fn](...args);
  throw new Error(`probe: unknown call ${target}.${fn}`);
}

export default {
  async fetch(request, env) {
    try {
      const result = await call(env, await request.json());
      return Response.json({ ok: true, result: result === undefined ? null : result });
    } catch (error) {
      return Response.json({ ok: false, error: String(error && error.message || error) });
    }
  },
};
