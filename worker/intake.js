// The intake Worker of interviewscam.com (ADR-0006). One ES module, no
// imports but the runtime's own, deployed by the operator with
// tools/intake.py and pinned by its SHA-256 in tools/sitecheck.py
// (INTAKE_WORKER_SHA256). Its rules and numbers repeat the INTAKE_*
// constants of tools/sitecheck.py, the single source; the tests under
// tests/worker/ prove the two equal and every rule at its bounds.
//
// POST https://intake.interviewscam.com/submit, multipart/form-data, from
// the forms on /report-a-scam/ and /corrections/. Each accepted submission
// is mailed to the operator through the send_email binding EMAIL, whose
// destination_address is fixed at deploy time. Nothing is stored but the
// limiter rows (part 11), and every outcome the code decides is a 303 to a
// static page of the site, so the Worker writes no text a reporter reads
// (part 6). The checks run cheapest first (part 3): method and path,
// Origin, the Rate Limiting binding RATE_LIMITER, the Durable Object
// IntakeLimiter, Content-Length, the body, the fields, the files, the
// global daily cap, the mail. Every failure of a limiter fails closed.

import { DurableObject } from "cloudflare:workers";

const SITE_ORIGIN = "https://interviewscam.com";
const PATH = "/submit";
const LIMITER_NAME = "intake";

// The pause notice is tried at most this often per UTC day (Numbers, "Global
// cap"): a send() that throws after the message went out must not mail the
// operator on every paused refusal.
const NOTICE_TRIES = 3;

const FIELD = (name, type, required, cap, autocomplete) => Object.freeze({ name, type, required, cap, autocomplete });

// The values of the INTAKE_* constants of tools/sitecheck.py
// (test_constants_match_worker compares them key by key).
export const INTAKE = Object.freeze({
  SITE_ORIGIN,
  SENT_URL: SITE_ORIGIN + "/sent/",
  NOT_SENT_URL: SITE_ORIGIN + "/not-sent/",
  ORIGIN: "https://intake.interviewscam.com",
  ACTION: "https://intake.interviewscam.com" + PATH,
  SENDER: "intake@interviewscam.com",
  FIELDS: Object.freeze({
    report: Object.freeze([
      FIELD("channel", "hidden", true, null, null),
      FIELD("name", "text", true, 200, "off"),
      FIELD("contact_start", "text", false, 200, "off"),
      FIELD("details", "textarea", true, 10000, "off"),
      FIELD("headers", "textarea", false, 32000, "off"),
      FIELD("email", "email", true, 254, "email"),
      FIELD("files", "file", false, null, null),
      FIELD("website", "honeypot", false, null, "off"),
    ]),
    correction: Object.freeze([
      FIELD("channel", "hidden", true, null, null),
      FIELD("page_url", "url", true, 976, "off"),
      FIELD("request", "textarea", true, 10000, "off"),
      FIELD("own_name", "checkbox", false, null, null),
      FIELD("email", "email", true, 254, "email"),
      FIELD("files", "file", false, null, null),
      FIELD("website", "honeypot", false, null, "off"),
    ]),
  }),
  IMAGE_TYPES: Object.freeze([
    ["image/png", "png", [[0, "89504e470d0a1a0a"]]],
    ["image/jpeg", "jpg", [[0, "ffd8ff"]]],
    ["image/gif", "gif", [[0, "474946383761"]]],
    ["image/gif", "gif", [[0, "474946383961"]]],
    ["image/webp", "webp", [[0, "52494646"], [8, "57454250"]]],
  ]),
  MAX_FILES: 10,
  MAX_UPLOAD_BYTES: 10 * 1024 * 1024,
  MAX_BODY: 10 * 1024 * 1024 + 327680,
  FILE_NAME_CAP: 100,
  CLIENT_LIMIT: 6,
  CLIENT_WINDOW_MS: 3600000,
  CLIENT_DAILY_MAILS: 3,
  DAILY_CAP: 50,
  NOTICE_TRIES,
  LIMITER_KEY_BYTES: 32,
  BURST_ABSENT_BINDING: "RATE_LIMITER_ABSENT",
  BURST_ABSENT_VALUE: "refused-by-cloudflare",
  RESULT_IDS: Object.freeze(["too-large", "too-many-files", "not-an-image", "missing-field", "too-long",
    "bad-address", "bad-page-url", "too-many-attempts", "paused", "not-accepted", "error"]),
});

const DAY_MS = 86400000;
const TEXT_TYPES = new Set(["text", "textarea", "email", "url"]);
const BASE_HEADERS = Object.freeze({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });

// ---------------------------------------------------------------------------
// Pure helpers, exported for tests/worker/probe.js.

// Lengths count UTF-16 code units after CRLF and CR become LF (part 5), the
// unit and the line breaks HTML maxlength counts.
export function normalizeText(value) {
  return String(value).replace(/\r\n?/g, "\n");
}

// Empty after trimming Unicode White_Space and U+200B, U+2060, U+FEFF
// (part 5): what HTML required lets through and the Worker refuses.
export function isBlank(value) {
  return /^[\p{White_Space}\u200B\u2060\uFEFF]*$/u.test(value);
}

// The HTML "valid e-mail address" grammar, which type="email" applies.
const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;

export function isValidEmail(value) {
  return EMAIL_RE.test(value);
}

// page_url must parse with the WHATWG URL parser to the site's origin, and
// hold no White_Space at all: a copied page URL has none, while the parser
// would percent-encode an inner space and let a second URL ride along
// ("https://interviewscam.com/x https://evil.example/") into the subject.
export function pageUrlOk(value) {
  if (/\p{White_Space}/u.test(value)) return false;
  try {
    return new URL(value).origin === SITE_ORIGIN;
  } catch {
    return false;
  }
}

// Part 7: http://, https:// and ftp:// become hxxp://, hxxps:// and
// fxp://, in any case, idempotently (the results never match again).
export function defangSchemes(value) {
  return String(value).replace(/(https?|ftp):\/\//gi, (match, scheme) =>
    ({ http: "hxxp", https: "hxxps", ftp: "fxp" })[scheme.toLowerCase()] + "://");
}

// Part 7, the subject: bidi controls and zero-width characters removed,
// whitespace collapsed, every other C0 or C1 control removed.
export function cleanSubject(value) {
  return String(value)
    .replace(/[\u200B-\u200F\u2060\uFEFF\u202A-\u202E\u2066-\u2069]/g, "")
    .replace(/\p{White_Space}+/gu, " ")
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, "")
    .replace(/ {2,}/g, " ")
    .trim();
}

// Part 7: the subject uses the raw value after the stripping above, never
// the URL serialization (percent-encoding could pass 998 characters), with
// the body's scheme rewrite, which keeps the length (fix round 1 of PR 2:
// a live URL in a report name reached the subject line).
export function subjectFor(channel, fields) {
  if (channel === "report") return "Report: " + defangSchemes(cleanSubject(fields.name));
  const prefix = fields.own_name === "yes" ? "Correction, own name: " : "Correction: ";
  return prefix + defangSchemes(cleanSubject(fields.page_url));
}

// Part 7, the body: C0 controls other than TAB and LF removed, then the
// scheme rewrite; the text is otherwise kept verbatim.
function bodyText(value) {
  return defangSchemes(normalizeText(value).replace(/[\u0000-\u0008\u000B-\u001F]/g, ""));
}

// One line: every White_Space character becomes a space (fix round 2 of PR
// 2). LF and TAB, and U+0085, U+2028 and U+2029, which line-splitting
// readers and mail views break on, would otherwise start a forged label
// line ("Own name: yes") in the body.
function oneLine(value) {
  return value.replace(/\p{White_Space}/gu, " ");
}

// Part 4: an original file name as context, on one line, cut to
// FILE_NAME_CAP UTF-16 code units without splitting a surrogate pair.
function fileNameText(value) {
  let text = oneLine(bodyText(value));
  if (text.length > INTAKE.FILE_NAME_CAP) {
    text = text.slice(0, INTAKE.FILE_NAME_CAP);
    if (/[\uD800-\uDBFF]$/.test(text)) text = text.slice(0, -1);
  }
  return text;
}

// Part 4: the image type by its magic bytes; the client's MIME type and
// file name are never read.
export function detectImageType(bytes) {
  for (const [type, ext, signature] of INTAKE.IMAGE_TYPES) {
    const match = signature.every(([offset, hex]) => {
      if (bytes.length < offset + hex.length / 2) return false;
      for (let i = 0; i < hex.length / 2; i++) {
        if (bytes[offset + i] !== parseInt(hex.slice(2 * i, 2 * i + 2), 16)) return false;
      }
      return true;
    });
    if (match) return { type, ext };
  }
  return null;
}

function parseIPv4(text) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!m) return null;
  const parts = m.slice(1);
  if (parts.some((p) => p.length > 1 && p[0] === "0")) return null;
  const nums = parts.map(Number);
  return nums.every((n) => n <= 255) ? nums : null;
}

function parseIPv6(text) {
  if (!/^[0-9A-Fa-f:.]+$/.test(text) || !text.includes(":")) return null;
  let head = text;
  let tail = [];
  if (text.includes(".")) {
    const cut = text.lastIndexOf(":");
    const v4 = parseIPv4(text.slice(cut + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    head = text.slice(0, cut + 1);
    if (!head.endsWith("::")) head = head.slice(0, -1);
  }
  const halves = head.split("::");
  if (halves.length > 2) return null;
  const groups = (part) => (part === "" ? [] : part.split(":"));
  const left = groups(halves[0]);
  const right = halves.length === 2 ? groups(halves[1]) : [];
  if ([...left, ...right].some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return null;
  const need = 8 - tail.length;
  let hextets;
  if (halves.length === 2) {
    if (left.length + right.length > need - 1) return null;
    hextets = [...left, ...Array(need - left.length - right.length).fill("0"), ...right];
  } else {
    if (left.length !== need) return null;
    hextets = left;
  }
  return [...hextets.map((g) => parseInt(g, 16)), ...tail];
}

// Part 11: the limiter key's material, the IPv4 /32 or the IPv6 /64 of
// CF-Connecting-IP; an IPv4-mapped IPv6 address is read as IPv4. No or an
// unreadable address shares one key, "unknown".
export function clientKeyMaterial(ip) {
  if (typeof ip !== "string") return "unknown";
  const v4 = parseIPv4(ip);
  if (v4) return "v4:" + v4.join(".");
  const v6 = parseIPv6(ip);
  if (!v6) return "unknown";
  if (v6.slice(0, 5).every((h) => h === 0) && v6[5] === 0xffff) {
    return "v4:" + [v6[6] >> 8, v6[6] & 255, v6[7] >> 8, v6[7] & 255].join(".");
  }
  return "v6:" + v6.slice(0, 4).map((h) => h.toString(16)).join(":");
}

// Numbers, "Window bound": attempts with at > now - window count, so an
// attempt exactly one window old no longer does.
export function limiterDecide(rows, now) {
  const count = rows.filter((at) => at > now - INTAKE.CLIENT_WINDOW_MS).length;
  return { count, allowed: count < INTAKE.CLIENT_LIMIT };
}

export function dayKey(now) {
  return new Date(now).toISOString().slice(0, 10);
}

function nextMidnight(now) {
  return (Math.floor(now / DAY_MS) + 1) * DAY_MS;
}

function hexBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return bytes;
}

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Part 11: HMAC-SHA-256 under the 32-byte secret LIMITER_KEY (64 hex
// digits). A malformed secret throws, and the request ends as #error.
async function limiterKey(secret, material) {
  if (typeof secret !== "string" || !new RegExp(`^[0-9a-f]{${2 * INTAKE.LIMITER_KEY_BYTES}}$`).test(secret)) {
    throw new Error("LIMITER_KEY is not 32 bytes in hex");
  }
  const key = await crypto.subtle.importKey("raw", hexBytes(secret), { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(material)));
}

// ---------------------------------------------------------------------------
// The submission.

function reject(id, code) {
  return { id, code };
}

// Part 5 and part 4, in the order of plan step 6: the closed field set,
// the honeypot, the fields, then the files (count, total, magic bytes).
export async function validate(form) {
  const entries = [...form.entries()];
  const channels = entries.filter(([name]) => name === "channel");
  if (channels.length !== 1 || typeof channels[0][1] !== "string"
      || !Object.hasOwn(INTAKE.FIELDS, channels[0][1])) {
    return reject("not-accepted", "E_CHANNEL");
  }
  const channel = channels[0][1];
  const spec = INTAKE.FIELDS[channel];
  const byName = new Map(spec.map((field) => [field.name, field]));
  const values = {};
  const files = [];
  for (const [name, value] of entries) {
    const field = byName.get(name);
    if (!field) return reject("not-accepted", "E_FIELD");
    if (field.type === "file") {
      // A part with an empty file name reaches formData() as a string; the
      // empty one is the browser's "nothing chosen" part.
      if (typeof value === "string") {
        if (value === "") continue;
        return reject("not-accepted", "E_FIELD");
      }
      files.push(value);
      continue;
    }
    if (typeof value !== "string") return reject("not-accepted", "E_FIELD");
    if (Object.hasOwn(values, name)) return reject("not-accepted", "E_DUPLICATE");
    values[name] = value;
  }
  if (values.website !== "") return reject("not-accepted", "E_HONEYPOT");
  if (Object.hasOwn(values, "own_name") && values.own_name !== "yes") return reject("not-accepted", "E_FIELD");

  const text = {};
  for (const field of spec) {
    if (TEXT_TYPES.has(field.type)) text[field.name] = normalizeText(values[field.name] ?? "");
  }
  for (const field of spec) {
    if (field.required && TEXT_TYPES.has(field.type) && isBlank(text[field.name])) {
      return reject("missing-field", "E_REQUIRED");
    }
  }
  for (const field of spec) {
    if (field.cap !== null && text[field.name].length > field.cap) return reject("too-long", "E_LENGTH");
  }
  if (!isValidEmail(text.email)) return reject("bad-address", "E_EMAIL");
  if (channel === "correction" && !pageUrlOk(text.page_url)) return reject("bad-page-url", "E_PAGE_URL");

  if (files.length > INTAKE.MAX_FILES) return reject("too-many-files", "E_FILE_COUNT");
  const total = files.reduce((sum, file) => sum + file.size, 0);
  if (total > INTAKE.MAX_UPLOAD_BYTES) return reject("too-large", "E_UPLOAD_SIZE");
  const attachments = [];
  const names = [];
  for (const file of files) {
    const content = await file.arrayBuffer();
    const kind = detectImageType(new Uint8Array(content));
    if (!kind) return reject("not-an-image", "E_FILE_TYPE");
    attachments.push({ content, filename: `evidence-${attachments.length + 1}.${kind.ext}`, type: kind.type,
      disposition: "attachment" });
    names.push(file.name);
  }
  return { channel, text, ownName: values.own_name === "yes", attachments, names };
}

const LABELS = Object.freeze({
  name: "Name", contact_start: "Where the contact started", details: "Details", headers: "Mail headers",
  email: "Reply address", page_url: "Page", request: "Request",
});
const BLOCK_FIELDS = new Set(["details", "headers", "request"]);

// Part 7: text only, from the fixed sender, no `to` (the binding's
// destination_address applies), replyTo the validated address.
function buildMail(checked) {
  const lines = [
    "Notice: the URL schemes http, https and ftp in this message were rewritten to hxxp, hxxps and fxp; bare domains were not changed.",
    `Channel: ${checked.channel}`,
  ];
  for (const field of INTAKE.FIELDS[checked.channel]) {
    if (field.type === "checkbox") lines.push(`Own name: ${checked.ownName ? "yes" : "no"}`);
    if (!Object.hasOwn(LABELS, field.name)) continue;
    const value = bodyText(checked.text[field.name]);
    // A single-line field stays on its line: a browser strips line breaks
    // from text, email and url inputs, so only a hand-made request sends
    // one, and it could forge a label line ("Own name: yes") below.
    if (BLOCK_FIELDS.has(field.name)) lines.push("", `${LABELS[field.name]}:`, value, "");
    else lines.push(`${LABELS[field.name]}: ${oneLine(value)}`);
  }
  if (checked.attachments.length) {
    lines.push("", "Files (attachment: original name, cut to 100 characters):");
    checked.attachments.forEach((item, i) => lines.push(`${item.filename}: ${fileNameText(checked.names[i])}`));
  }
  const fields = { ...checked.text, own_name: checked.ownName ? "yes" : "" };
  const mail = {
    from: INTAKE.SENDER,
    replyTo: checked.text.email,
    subject: subjectFor(checked.channel, fields),
    text: lines.join("\n") + "\n",
  };
  if (checked.attachments.length) mail.attachments = checked.attachments;
  return mail;
}

// Numbers, "Global cap": one notice to the operator on the first refusal
// of the UTC day. It never names a reporter and has no reply address.
async function sendNotice(env, day) {
  try {
    await env.EMAIL.send({
      from: INTAKE.SENDER,
      subject: `Intake paused: ${INTAKE.DAILY_CAP} submissions on ${day}`,
      text: `The daily cap of ${INTAKE.DAILY_CAP} mailed submissions was reached on ${day} (UTC). `
        + "Until 00:00 UTC the form answers /not-sent/#paused, which points reporters to the email address.\n",
    });
    return true;
  } catch {
    return false;
  }
}

// Part 11: event codes only, never a field value, an address or a key.
function log(event, code) {
  console.log(code ? `intake event=${event} code=${code}` : `intake event=${event}`);
}

function empty(status, extra = {}) {
  return new Response(null, { status, headers: { ...BASE_HEADERS, ...extra } });
}

function redirect(id, code) {
  log(id, code);
  const location = id === "sent" ? INTAKE.SENT_URL : `${INTAKE.NOT_SENT_URL}#${id}`;
  return empty(303, { Location: location });
}

async function handle(request, env) {
  if (request.method !== "POST") return empty(405, { Allow: "POST" });
  if (new URL(request.url).pathname !== PATH) return empty(404);

  const origin = request.headers.get("Origin");
  if (origin !== null && origin !== SITE_ORIGIN) return redirect("not-accepted", "E_ORIGIN");

  const key = await limiterKey(env.LIMITER_KEY, clientKeyMaterial(request.headers.get("CF-Connecting-IP")));
  // The Rate Limiting binding, or the explicit no-binding mode of ADR-0006
  // part 3 step 3 (deployed with `tools/intake.py deploy
  // --without-rate-limiter`, checked by verify). Neither is #error.
  if (env.RATE_LIMITER !== undefined) {
    let burst;
    try {
      burst = await env.RATE_LIMITER.limit({ key });
    } catch {
      return redirect("error", "E_BURST");
    }
    if (!burst || burst.success !== true) return redirect("too-many-attempts", "E_BURST_LIMIT");
  } else if (env[INTAKE.BURST_ABSENT_BINDING] !== INTAKE.BURST_ABSENT_VALUE) {
    return redirect("error", "E_BURST_MISSING");
  }

  const limiter = env.LIMITER.get(env.LIMITER.idFromName(LIMITER_NAME));
  const now = Date.now();
  let verdict;
  try {
    verdict = await limiter.attempt(key, now);
  } catch {
    return redirect("error", "E_LIMITER");
  }
  if (!verdict || verdict.ok !== true) {
    return redirect("too-many-attempts", verdict && verdict.reason === "client-mails" ? "E_CLIENT_MAILS" : "E_CLIENT_LIMIT");
  }

  // Refused before the body is read: no Content-Length (a chunked body) or
  // one above INTAKE_MAX_BODY.
  const length = request.headers.get("Content-Length");
  if (length === null || !/^[0-9]{1,15}$/.test(length) || Number(length) > INTAKE.MAX_BODY) {
    return redirect("too-large", "E_BODY_SIZE");
  }
  if (!/^multipart\/form-data\s*;/i.test(request.headers.get("Content-Type") || "")) {
    return redirect("not-accepted", "E_CONTENT_TYPE");
  }
  let form;
  try {
    form = await request.formData();
  } catch {
    return redirect("not-accepted", "E_PARSE");
  }
  const checked = await validate(form);
  if (checked.id) return redirect(checked.id, checked.code);

  // A fresh time for the daily caps: the body upload may have run past
  // 00:00 UTC since `now` (fix round 1 of PR 2), and the mail goes out on
  // the day it is sent. The limiter also never counts on a day older than
  // the newest time it has seen, and names the day it counted on.
  const sendNow = Date.now();
  let slot;
  try {
    slot = await limiter.reserve(key, sendNow);
  } catch {
    return redirect("error", "E_LIMITER");
  }
  if (!slot || slot.ok !== true) {
    if (slot && slot.reason === "paused") {
      // A notice that fails to send is reopened, so the next refusal of the
      // day tries again; the code E_NOTICE marks the log line.
      if (slot.notice === true && !(await sendNotice(env, slot.day))) {
        try {
          await limiter.noticeFailed(slot.day);
        } catch {
          log("paused", "E_NOTICE_REOPEN");
        }
        return redirect("paused", "E_NOTICE");
      }
      return redirect("paused", "E_DAILY_CAP");
    }
    return redirect("too-many-attempts", "E_CLIENT_MAILS");
  }
  try {
    await env.EMAIL.send(buildMail(checked));
  } catch {
    try {
      await limiter.refund(key, slot.day);
    } catch {
      log("error", "E_REFUND");
    }
    return redirect("error", "E_SEND");
  }
  return redirect("sent");
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch {
      return redirect("error", "E_UNCAUGHT");
    }
  },
};

// ---------------------------------------------------------------------------
// The limiter (part 3 step 4, part 11, Numbers "Quota bounds per source").
// One instance (LIMITER_NAME) holds three WITHOUT ROWID tables, so each
// insert, update or delete writes one row: attempts(key, at, seq), one row
// per counted attempt (seq tells apart attempts of one key in the same ms);
// mails(day, key, n), a key's mailed submissions per UTC day; days(day, n),
// the day's mailed submissions, where n = DAILY_CAP + 1 records that the
// notice went out. A refused attempt is answered after a read, with no
// write. One alarm, at the earliest expiry: an attempt row 3,600 s after
// it, a day row at the next 00:00 UTC. now comes from the caller (the
// Worker's Date.now(), or the probe's injected time), the alarm uses its
// own clock.

function checkArgs(key, now) {
  if (typeof key !== "string" || !/^[0-9a-f]{64}$/.test(key)) throw new TypeError("limiter: bad key");
  if (!Number.isSafeInteger(now) || now < 0) throw new TypeError("limiter: bad time");
}

function checkDay(day) {
  if (typeof day !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(day)) throw new TypeError("limiter: bad day");
}

function dayStart(day) {
  return Date.parse(`${day}T00:00:00.000Z`);
}

export class IntakeLimiter extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, at INTEGER NOT NULL, "
      + "seq INTEGER NOT NULL, PRIMARY KEY (key, at, seq)) WITHOUT ROWID");
    this.sql.exec("CREATE TABLE IF NOT EXISTS mails (day TEXT NOT NULL, key TEXT NOT NULL, "
      + "n INTEGER NOT NULL, PRIMARY KEY (day, key)) WITHOUT ROWID");
    this.sql.exec("CREATE TABLE IF NOT EXISTS days (day TEXT NOT NULL, n INTEGER NOT NULL, "
      + "PRIMARY KEY (day)) WITHOUT ROWID");
  }

  // The newest time this instance has seen (fix round 1 of PR 2): a request
  // whose body upload ran past 00:00 UTC must not count on a day whose rows
  // a later request has already deleted.
  latest(now) {
    this.newest = Math.max(this.newest || 0, now);
    return this.newest;
  }

  // On access, only the key's own expired attempt rows (a range of the
  // primary key) and the rows of past days; the alarm deletes the rest.
  expire(key, now) {
    this.sql.exec("DELETE FROM attempts WHERE key = ? AND at <= ?", key, now - INTAKE.CLIENT_WINDOW_MS);
    const today = dayKey(now);
    this.sql.exec("DELETE FROM mails WHERE day < ?", today);
    this.sql.exec("DELETE FROM days WHERE day < ?", today);
  }

  mailCount(day, key) {
    const row = this.sql.exec("SELECT n FROM mails WHERE day = ? AND key = ?", day, key).toArray()[0];
    return row ? row.n : 0;
  }

  async schedule(at) {
    const current = await this.ctx.storage.getAlarm();
    if (current === null || current > at) await this.ctx.storage.setAlarm(at);
  }

  async attempt(key, now) {
    checkArgs(key, now);
    this.latest(now);
    this.expire(key, now);
    const rows = this.sql.exec("SELECT at FROM attempts WHERE key = ?", key).toArray().map((r) => r.at);
    if (!limiterDecide(rows, now).allowed) return { ok: false, reason: "client-limit" };
    if (this.mailCount(dayKey(now), key) >= INTAKE.CLIENT_DAILY_MAILS) return { ok: false, reason: "client-mails" };
    const seq = rows.filter((at) => at === now).length;
    this.sql.exec("INSERT INTO attempts (key, at, seq) VALUES (?, ?, ?)", key, now, seq);
    await this.schedule(now + INTAKE.CLIENT_WINDOW_MS);
    return { ok: true };
  }

  async reserve(key, now) {
    checkArgs(key, now);
    const day = dayKey(this.latest(now));
    if (this.mailCount(day, key) >= INTAKE.CLIENT_DAILY_MAILS) return { ok: false, reason: "client-mails", day };
    const row = this.sql.exec("SELECT n FROM days WHERE day = ?", day).toArray()[0];
    const total = row ? row.n : 0;
    if (total >= INTAKE.DAILY_CAP) {
      // The notice state lives in days.n above the cap (fix round 2 of PR 2):
      // an even step (0, 2, 4) means "send a notice" (none yet, or the last
      // try failed), an odd one (1, 3, 5) a try in flight or sent, and
      // 2 * NOTICE_TRIES the tries used up. So at most NOTICE_TRIES notices
      // per UTC day, even when send() fails after the message went out.
      const step = total - INTAKE.DAILY_CAP;
      if (step % 2 === 0 && step < 2 * NOTICE_TRIES) {
        this.sql.exec("UPDATE days SET n = ? WHERE day = ?", total + 1, day);
        return { ok: false, reason: "paused", notice: true, day };
      }
      return { ok: false, reason: "paused", notice: false, day };
    }
    this.sql.exec("INSERT INTO mails (day, key, n) VALUES (?, ?, 1) ON CONFLICT (day, key) DO UPDATE SET n = n + 1",
      day, key);
    this.sql.exec("INSERT INTO days (day, n) VALUES (?, 1) ON CONFLICT (day) DO UPDATE SET n = n + 1", day);
    await this.schedule((dayStart(day) + DAY_MS));
    return { ok: true, day };
  }

  // A notice that failed to send: the next refusal of the day tries again,
  // until NOTICE_TRIES tries are used up.
  noticeFailed(day) {
    checkDay(day);
    this.sql.exec("UPDATE days SET n = n + 1 WHERE day = ? AND n > ? AND (n - ?) % 2 = 1",
      day, INTAKE.DAILY_CAP, INTAKE.DAILY_CAP);
    return { ok: true };
  }

  // A failed send() gives the slot back; once the notice went out
  // (n = DAILY_CAP + 1) the day stays paused.
  refund(key, day) {
    checkArgs(key, 0);
    checkDay(day);
    this.sql.exec("UPDATE mails SET n = n - 1 WHERE day = ? AND key = ? AND n > 0", day, key);
    this.sql.exec("UPDATE days SET n = n - 1 WHERE day = ? AND n > 0 AND n <= ?", day, INTAKE.DAILY_CAP);
    return { ok: true };
  }

  async purge(now) {
    if (!Number.isSafeInteger(now) || now < 0) throw new TypeError("limiter: bad time");
    this.sql.exec("DELETE FROM attempts WHERE at <= ?", now - INTAKE.CLIENT_WINDOW_MS);
    this.sql.exec("DELETE FROM mails WHERE day < ?", dayKey(now));
    this.sql.exec("DELETE FROM days WHERE day < ?", dayKey(now));
    const first = this.sql.exec("SELECT min(at) AS at FROM attempts").one().at;
    const daily = this.sql.exec("SELECT (SELECT count(*) FROM mails) + (SELECT count(*) FROM days) AS n").one().n;
    let next = first === null ? null : first + INTAKE.CLIENT_WINDOW_MS;
    if (daily > 0) next = next === null ? nextMidnight(now) : Math.min(next, nextMidnight(now));
    if (next === null) {
      // Nothing left to count: no later request can need the newest time.
      this.newest = 0;
      await this.ctx.storage.deleteAlarm();
    } else {
      await this.ctx.storage.setAlarm(next);
    }
    return { ok: true };
  }

  async alarm() {
    await this.purge(Date.now());
  }

  async rows() {
    return {
      attempts: this.sql.exec("SELECT key, at, seq FROM attempts ORDER BY key, at, seq").toArray(),
      mails: this.sql.exec("SELECT day, key, n FROM mails ORDER BY day, key").toArray(),
      days: this.sql.exec("SELECT day, n FROM days ORDER BY day").toArray(),
      alarm: await this.ctx.storage.getAlarm(),
    };
  }
}
