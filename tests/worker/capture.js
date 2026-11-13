// The send_email binding EMAIL of tests/worker/config.capnp: an RPC service
// that records every send() call instead of mailing (ADR-0006 part 7). The
// probe reads, clears and breaks it through the methods below. Attachments
// are kept as their size and SHA-256, so a 10 MiB submission costs no copy.

import { WorkerEntrypoint } from "cloudflare:workers";

let sent = [];
let failMode = "";

// What the send_email binding enforces by the Email Sending docs (Workers
// API and send bindings pages, read 2026-11-12; ADR-0006 Context): a sender
// on an onboarded domain; with destination_address, `to` unset (the
// configured address applies) or that address; a subject (at most 998
// characters, ADR-0006 Context); at most 32 attachments, each with content,
// filename, type and disposition "attachment" or "inline"; the whole
// message at most 25 MiB. A message that breaks one is refused with an
// error, as the binding would, so a Worker change that sends such a message
// fails its tests instead of passing them.
const SENDER_DOMAIN = "@interviewscam.com";
const DESTINATION = "operator@example.com";
const MAX_ATTACHMENTS = 32;
const MAX_MESSAGE = 25 * 1024 * 1024;

function refuse(message) {
  const error = new Error(`capture: ${message}`);
  error.code = "E_VALIDATION_ERROR";
  throw error;
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
  if (message.to !== undefined && message.to !== null && message.to !== DESTINATION) {
    refuse("recipient other than the binding's destination_address");
  }
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
