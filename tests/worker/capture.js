// The send_email binding EMAIL of tests/worker/config.capnp: an RPC service
// that records every send() call instead of mailing (ADR-0006 part 7). The
// probe reads, clears and breaks it through the methods below. Attachments
// are kept as their size and SHA-256, so a 10 MiB submission costs no copy.

import { WorkerEntrypoint } from "cloudflare:workers";

let sent = [];
let failMode = "";

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default class Capture extends WorkerEntrypoint {
  async send(message) {
    if (failMode === "throw") {
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
