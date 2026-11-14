// The send_email binding EMAIL of tests/worker/config.capnp: an RPC service
// that records every send() call instead of mailing (ADR-0006 part 7). The
// probe reads, clears and breaks it through the methods below. Attachments
// are kept as their size and SHA-256, so a 10 MiB submission costs no copy.

import { WorkerEntrypoint } from "cloudflare:workers";

let sent = [];
let failMode = "";

// What the send_email binding enforces by the Email Sending docs (Workers
// API and send bindings pages, read 2026-11-12; ADR-0006 Context): a sender
// on an onboarded domain; a subject (at most 998 characters, ADR-0006
// Context); at most 32 attachments, each with content, filename, type and
// disposition "attachment" or "inline"; the whole message at most 25 MiB.
// The recipient as the live binding refused and accepted it (ADR-0006
// Status, amended 2026-11-14: throwaway probe Workers on Workers Free with
// Email Routing only, a binding with destination_address), not as the send
// bindings page states it (a missing `to` uses the destination): no `to`
// (probes A, B) is a TypeError without a code; `to: null` (probe E) and
// `to: []` (probe F) are TypeErrors; `to` another address (probe H) is an
// Error with the code E_RECIPIENT_NOT_ALLOWED whose message names the
// address; `to` the destination as a string was sent (probes C, G).
// Stricter than live where no probe looked, on purpose: `to: ""` is a
// TypeError, `to` must be exactly the string DESTINATION (an array, an
// object or another case of the address is refused), and a `cc` or `bcc`
// key is refused with E_RECIPIENT_NOT_ALLOWED; a Worker change to such a
// shape fails here and needs a live probe first. A message that breaks one
// rule is refused with an error, as the binding would, so a Worker change
// that sends such a message fails its tests instead of passing them.
const SENDER_DOMAIN = "@interviewscam.com";
const DESTINATION = "operator@example.com";
const MAX_ATTACHMENTS = 32;
const MAX_MESSAGE = 25 * 1024 * 1024;

function refuse(message, code = "E_VALIDATION_ERROR") {
  const error = new Error(code === "E_VALIDATION_ERROR" ? `capture: ${message}` : message);
  error.code = code;
  throw error;
}

// The live binding's messages (probes A, E and F), kept verbatim.
const NO_RECIPIENT = 'Email must have at least one recipient in "to", "cc", or "bcc".';
const NULL_RECIPIENT = "Cannot initialize N10edgeworker3api12EmailAddressE with required members from an "
  + "undefined or null value.";

function checkRecipient(message) {
  if (!Object.hasOwn(message, "to") || message.to === undefined) throw new TypeError(NO_RECIPIENT);
  const to = message.to;
  if (to === null) throw new TypeError(NULL_RECIPIENT);
  if (Array.isArray(to) && to.length === 0) throw new TypeError(NO_RECIPIENT);
  if (to === "") throw new TypeError(NO_RECIPIENT);
  if (typeof to === "string" && to !== DESTINATION) refuse(`email to ${to} not allowed`, "E_RECIPIENT_NOT_ALLOWED");
  if (to !== DESTINATION) refuse("capture: a recipient shape no live probe covered", "E_RECIPIENT_NOT_ALLOWED");
  for (const key of ["cc", "bcc"]) {
    if (Object.hasOwn(message, key)) refuse(`capture: a ${key} key, which no live probe covered`,
      "E_RECIPIENT_NOT_ALLOWED");
  }
}

function size(content) {
  if (content instanceof ArrayBuffer) return content.byteLength;
  if (ArrayBuffer.isView(content)) return content.byteLength;
  if (typeof content === "string") return content.length;
  return -1;
}

function check(message) {
  if (!message || typeof message !== "object") refuse("no message");
  const from = typeof message.from === "object" && message.from ? message.from.email : message.from;
  if (typeof from !== "string" || !from.endsWith(SENDER_DOMAIN)) refuse("sender not on an onboarded domain");
  checkRecipient(message);
  if (typeof message.subject !== "string" || message.subject.length > 998) refuse("subject missing or over 998");
  if (message.replyTo !== undefined && typeof message.replyTo !== "string"
      && !(message.replyTo && typeof message.replyTo.email === "string")) refuse("replyTo malformed");
  const attachments = message.attachments === undefined ? [] : message.attachments;
  if (!Array.isArray(attachments) || attachments.length > MAX_ATTACHMENTS) refuse("attachments malformed or over 32");
  let total = ["subject", "text", "html"].reduce((sum, key) => sum + (typeof message[key] === "string"
    ? new TextEncoder().encode(message[key]).length : 0), 0);
  for (const item of attachments) {
    if (!item || size(item.content) < 0 || typeof item.filename !== "string" || typeof item.type !== "string"
        || !["attachment", "inline"].includes(item.disposition)) refuse("attachment malformed");
    total += Math.ceil(size(item.content) / 3) * 4;
  }
  if (total > MAX_MESSAGE) refuse("message over 25 MiB");
}

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default class Capture extends WorkerEntrypoint {
  async send(message) {
    check(message);
    if (failMode === "throw" || (failMode === "notice" && String(message.subject).startsWith("Intake paused"))) {
      const error = new Error("capture: send failure requested by the test");
      error.code = "E_TEST_FAILURE";
      throw error;
    }
    const record = { keys: Object.keys(message).sort() };
    for (const key of ["to", "from", "subject", "text", "html", "replyTo", "cc", "bcc", "headers"]) {
      if (key in message) record[key] = message[key] === undefined ? null : message[key];
    }
    record.attachments = [];
    for (const item of message.attachments || []) {
      const content = item.content;
      const buffer = content instanceof ArrayBuffer ? content
        : ArrayBuffer.isView(content) ? content.buffer.slice(content.byteOffset, content.byteOffset + content.byteLength)
        : new TextEncoder().encode(String(content)).buffer;
      record.attachments.push({
        keys: Object.keys(item).sort(),
        filename: item.filename,
        type: item.type,
        disposition: item.disposition,
        binary: content instanceof ArrayBuffer || ArrayBuffer.isView(content),
        size: buffer.byteLength,
        sha256: await sha256Hex(buffer),
      });
    }
    sent.push(record);
    return { messageId: `test-${sent.length}` };
  }

  // The verdict check() gives a message, as data: null when it is
  // accepted, else the error's name, code (null when it has none) and
  // message. The stand-in's table pins these without relying on how workerd
  // carries an error's properties across RPC.
  verdict(message) {
    try {
      check(message);
      return null;
    } catch (error) {
      return { name: error.name, code: error.code === undefined ? null : error.code, message: error.message };
    }
  }

  list() {
    return sent;
  }

  clear() {
    sent = [];
    failMode = "";
    return true;
  }

  setFail(mode) {
    failMode = String(mode || "");
    return failMode;
  }

  fetch() {
    return new Response(null, { status: 404 });
  }
}
