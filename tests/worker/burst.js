// The Rate Limiting binding RATE_LIMITER of tests/worker/config.capnp
// (ADR-0006 part 3 step 3): limit({key}) answers {success} from a count of
// the key's calls in the last period, as the production binding does per
// location (it is approximate there; here it is exact). The probe sets the
// limit and period from tools/sitecheck.py, switches it off for the cases
// that test the Durable Object alone, or makes it throw.

import { WorkerEntrypoint } from "cloudflare:workers";

let calls = new Map();
let limit = 6;
let periodMs = 60000;
let mode = "on";

export default class Burst extends WorkerEntrypoint {
  async limit(options) {
    if (mode === "throw") throw new Error("burst: failure requested by the test");
    const key = options && options.key;
    if (typeof key !== "string") throw new TypeError("burst: key must be a string");
    if (mode === "off") return { success: true };
    const now = Date.now();
    const recent = (calls.get(key) || []).filter((at) => at > now - periodMs);
    const success = recent.length < limit;
    recent.push(now);
    calls.set(key, recent);
    return { success };
  }

  reset(settings) {
    calls = new Map();
    limit = settings.limit;
    periodMs = settings.period * 1000;
    mode = settings.mode;
    return true;
  }

  keys() {
    return [...calls.keys()];
  }

  fetch() {
    return new Response(null, { status: 404 });
  }
}
