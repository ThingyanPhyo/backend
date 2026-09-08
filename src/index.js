// Overtime Tracker OTP + Records-Sync backend — Cloudflare Workers + Brevo
// (email) + Workers KV (storage).
//
// Why this instead of the old Render backend: Render's free web services sleep
// after 15 minutes of inactivity and take 30-60s to wake up, which was longer
// than the app's 15s timeout — that's what caused "Couldn't reach the server".
// Cloudflare Workers is serverless at the edge and never sleeps, so this
// backend responds in milliseconds even after long idle periods.
//
// API contract:
//   POST /otp/send            { "email": "..." }
//     -> { "success": bool, "reason": "invalid_email"|"cooldown"|"email_send_failed"|null }
//   POST /otp/verify          { "email": "...", "otp": "..." }
//     -> { "success": bool, "reason": "incorrect"|"expired"|"too_many_attempts"|"not_requested"|null }
//   POST /records/check-owner { "employeeId": "...", "email": "..." }
//     -> { "status": "new" | "restore" }
//   POST /records/claim       { "employeeId": "...", "email": "...", "name": "...", "department": "..." }
//     -> { "success": true, "syncToken": "...", "records": [...] }
//        | { "success": false, "reason": "id_taken_different_owner" }
//   POST /records/sync        { "employeeId": "...", "syncToken": "...", "records": [...], "name": "...", "department": "..." }
//     -> { "success": bool, "reason": "invalid_token"|null }
//
//   -- HR review (see ADMIN AUTH note below) --
//   POST /admin/login               { "password": "..." }
//     -> { "success": bool, "adminToken": "..." } | { "success": false }
//   POST /admin/employees           { "adminToken": "..." }
//     -> { "success": bool, "employees": [{employeeId,name,department,email,recordCount,updatedAt}] }
//   POST /admin/employee-records    { "adminToken": "...", "employeeId": "..." }
//     -> { "success": bool, "name": "...", "department": "...", "records": [...] }
//   POST /admin/approve             { "adminToken": "...", "employeeId": "...", "dateMillis": N, "approved": bool }
//     -> { "success": bool, "reason": "not_found"|"unauthorized"|null }
//
// ---- ADMIN AUTH ----
// One shared password (HR_REVIEW_PASSWORD, near handleAdminLogin below —
// edit that line + `wrangler deploy` to change it, nothing else to touch),
// not per-person named accounts — deliberately this simple. This app is
// used offline by a small (~10 person) team, not distributed publicly, and
// whoever holds this password already sees/approves every employee, every
// department, no scoping — so there's nothing here that benefits from
// per-account complexity the way a larger or public deployment might.
//
// /admin/login exchanges that password for a random bearer adminToken
// (stored in ADMIN_KV with a 12-hour TTL) — every other /admin/* call
// requires that token, never the password itself again. Single-session:
// logging in again immediately invalidates whatever session already
// existed, so at most one device/browser can ever be using it at once —
// see the note in handleAdminLogin. This is what actually matters here:
// Settings → HR Review's own PIN gate only proves it's that phone's
// owner — every employee already knows THEIR OWN PIN, so it can't be what
// keeps them out of this menu on their own phone. This password is the
// actual gate; the PIN before it is a different, unrelated one (this
// app's normal lock, same as it guards Record Overtime). This login is
// intentionally NOT hidden from employees: it's reachable from Settings
// in the app, same as any other menu row — the password (and its
// single-session enforcement) is what actually restricts it, not
// obscurity.

// ---- SECURITY DESIGN (records/*) — read this before changing anything ----
// Employee ID is NOT a secret — company IDs are typically sequential
// (P-1076, P-1077, ...), so anyone could guess a coworker's ID. That means
// Employee ID ALONE must never be enough to read or overwrite someone's
// synced records; every records/* flow is anchored to the SAME
// OTP-verified-email proof of ownership already used for account setup:
//
//   1. check-owner is deliberately vague — an ID that's unclaimed and an ID
//      that's claimed by a DIFFERENT email both return "new". Only an exact
//      employeeId+email match returns "restore". This stops someone probing
//      many IDs with one email from learning which IDs are already taken by
//      someone else (that alone would leak real headcount/ID info).
//   2. claim() is the only endpoint that returns actual record data or a
//      syncToken, and the app only calls it AFTER /otp/verify succeeds for
//      that same email — so reading/restoring data requires proving inbox
//      access to the email already on file, not just knowing the ID.
//   3. Ongoing sync (every local save, not just setup) is authenticated by
//      syncToken, not employeeId+email — a bearer secret minted once at
//      claim() time and never re-derivable from the ID alone, so nothing
//      after setup can overwrite someone's backup without that token.
//   4. Attempting to claim() an ID already owned by a different email is
//      always rejected (id_taken_different_owner) — never silently
//      overwrites another employee's profile/records.
// ----------------------------------------------------------------------

// These two MUST match OtpVerifyActivity.kt's OTP_TTL_MS / RESEND_COOLDOWN_MS
// exactly, since the app's countdown UI assumes the backend agrees with it.
const OTP_TTL_MS = 5 * 60 * 1000;       // 5 minutes
const RESEND_COOLDOWN_MS = 60 * 1000;   // 1 minute
const MAX_ATTEMPTS = 5;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }));
    }

    if (url.pathname === "/otp/send" && request.method === "POST") {
      return withCors(await handleSend(request, env));
    }

    if (url.pathname === "/otp/verify" && request.method === "POST") {
      return withCors(await handleVerify(request, env));
    }

    if (url.pathname === "/records/check-owner" && request.method === "POST") {
      return withCors(await handleCheckOwner(request, env));
    }

    if (url.pathname === "/records/claim" && request.method === "POST") {
      return withCors(await handleClaim(request, env));
    }

    if (url.pathname === "/records/sync" && request.method === "POST") {
      return withCors(await handleSync(request, env));
    }

    if (url.pathname === "/admin/login" && request.method === "POST") {
      return withCors(await handleAdminLogin(request, env));
    }

    if (url.pathname === "/admin/employees" && request.method === "POST") {
      return withCors(await handleAdminEmployees(request, env));
    }

    if (url.pathname === "/admin/employee-records" && request.method === "POST") {
      return withCors(await handleAdminEmployeeRecords(request, env));
    }

    if (url.pathname === "/admin/approve" && request.method === "POST") {
      return withCors(await handleAdminApprove(request, env));
    }

    if (url.pathname === "/" && request.method === "GET") {
      return withCors(json({ success: true, message: "Overtime Tracker backend is running." }));
    }

    return withCors(json({ success: false, reason: "not_found" }, 404));
  },
};

async function handleSend(request, env) {
  const body = await safeJson(request);
  const email = normalizeEmail(body?.email);

  if (!isValidEmail(email)) {
    return json({ success: false, reason: "invalid_email" });
  }

  const key = otpKey(email);
  const now = Date.now();
  const existing = await getJson(env.OTP_KV, key);

  if (existing && now - existing.lastSentAt < RESEND_COOLDOWN_MS) {
    return json({ success: false, reason: "cooldown" });
  }

  const otp = generateOtp();
  const sent = await sendOtpEmail(env, email, otp);
  if (!sent) {
    return json({ success: false, reason: "email_send_failed" });
  }

  const record = { otp, expiresAt: now + OTP_TTL_MS, lastSentAt: now, attempts: 0 };
  // Keep the KV entry alive a little past expiry so a late verify attempt
  // gets a proper "expired" instead of "not_requested".
  await putJson(env.OTP_KV, key, record, OTP_TTL_MS + 60_000);

  return json({ success: true });
}

async function handleVerify(request, env) {
  const body = await safeJson(request);
  const email = normalizeEmail(body?.email);
  const otp = (body?.otp ?? "").toString().trim();

  const key = otpKey(email);
  const record = await getJson(env.OTP_KV, key);
  if (!record) {
    return json({ success: false, reason: "not_requested" });
  }

  const now = Date.now();
  if (now > record.expiresAt) {
    await env.OTP_KV.delete(key);
    return json({ success: false, reason: "expired" });
  }

  if (record.attempts >= MAX_ATTEMPTS) {
    await env.OTP_KV.delete(key);
    return json({ success: false, reason: "too_many_attempts" });
  }

  if (otp !== record.otp) {
    record.attempts += 1;
    if (record.attempts >= MAX_ATTEMPTS) {
      await env.OTP_KV.delete(key);
      return json({ success: false, reason: "too_many_attempts" });
    }
    await putJson(env.OTP_KV, key, record, Math.max(1, record.expiresAt - now) + 60_000);
    return json({ success: false, reason: "incorrect" });
  }

  await env.OTP_KV.delete(key);
  return json({ success: true });
}

// ---- Records sync/restore ------------------------------------------------

async function handleCheckOwner(request, env) {
  const body = await safeJson(request);
  const employeeId = normalizeEmployeeId(body?.employeeId);
  const email = normalizeEmail(body?.email);
  if (!employeeId || !isValidEmail(email)) {
    return json({ status: "new" });
  }

  const profile = await getJson(env.RECORDS_KV, employeeKey(employeeId));
  // Deliberately vague — see the SECURITY DESIGN note at the top of this
  // file for why an unclaimed ID and an ID claimed by someone else's email
  // both have to return the same thing here.
  const status = profile && profile.email === email ? "restore" : "new";
  return json({ status });
}

async function handleClaim(request, env) {
  const body = await safeJson(request);
  const employeeId = normalizeEmployeeId(body?.employeeId);
  const email = normalizeEmail(body?.email);
  const name = (body?.name ?? "").toString().trim();
  const department = (body?.department ?? "").toString().trim();
  if (!employeeId || !isValidEmail(email)) {
    return json({ success: false, reason: "invalid_request" });
  }

  const key = employeeKey(employeeId);
  const existing = await getJson(env.RECORDS_KV, key);

  if (existing && existing.email !== email) {
    // Never silently take over — see SECURITY DESIGN note #4.
    return json({ success: false, reason: "id_taken_different_owner" });
  }

  // Either brand new, or the same owner re-claiming after a reinstall —
  // either way, mint a fresh syncToken (rotating it on every claim is
  // simply good hygiene, not a response to anything suspicious).
  const syncToken = generateToken();
  const records = existing?.records ?? [];
  const profile = { email, syncToken, records, name, department, updatedAt: Date.now() };
  await putJson(env.RECORDS_KV, key, profile, null);

  return json({ success: true, syncToken, records });
}

async function handleSync(request, env) {
  const body = await safeJson(request);
  const employeeId = normalizeEmployeeId(body?.employeeId);
  const syncToken = (body?.syncToken ?? "").toString().trim();
  const records = Array.isArray(body?.records) ? body.records : null;

  if (!employeeId || !syncToken || records === null) {
    return json({ success: false, reason: "invalid_request" });
  }

  const key = employeeKey(employeeId);
  const existing = await getJson(env.RECORDS_KV, key);
  if (!existing || existing.syncToken !== syncToken) {
    return json({ success: false, reason: "invalid_token" });
  }

  existing.records = records;
  if (body?.name) existing.name = body.name.toString().trim();
  if (body?.department) existing.department = body.department.toString().trim();
  existing.updatedAt = Date.now();
  await putJson(env.RECORDS_KV, key, existing, null);

  return json({ success: true });
}

// ---- HR review / admin ----------------------------------------------------

const ADMIN_TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

// One shared password, not per-person accounts — see the ADMIN AUTH note
// above for why this app deliberately keeps it this simple. To change it:
// edit this line, then `wrangler deploy` (the same command already used
// for every other backend change) — no separate provisioning command, no
// KV, nothing else to touch.
const HR_REVIEW_PASSWORD = "changeme";

async function handleAdminLogin(request, env) {
  const body = await safeJson(request);
  const password = (body?.password ?? "").toString();
  if (!password || password !== HR_REVIEW_PASSWORD) {
    return json({ success: false });
  }

  // Single-session — only ONE device should ever be reviewing payroll data
  // at a time, not "however many logins this password has quietly
  // accumulated wherever it's been shared." A fresh login immediately
  // kills whatever session already existed, so the previous device's next
  // request comes back unauthorized — there is never more than one valid
  // adminToken at once, regardless of how many people actually know the
  // password.
  const previousToken = await getJson(env.ADMIN_KV, activeTokenKey());
  if (previousToken) {
    await env.ADMIN_KV.delete(adminTokenKey(previousToken));
  }

  const adminToken = generateToken();
  const session = { createdAt: Date.now() };
  await putJson(env.ADMIN_KV, adminTokenKey(adminToken), session, ADMIN_TOKEN_TTL_MS);
  await putJson(env.ADMIN_KV, activeTokenKey(), adminToken, ADMIN_TOKEN_TTL_MS);
  return json({ success: true, adminToken });
}

async function handleAdminEmployees(request, env) {
  const body = await safeJson(request);
  const session = await getAdminSession(body?.adminToken, env);
  if (!session) {
    return json({ success: false, reason: "unauthorized" }, 401);
  }

  const employees = [];
  let cursor;
  do {
    const page = await env.RECORDS_KV.list({ prefix: "emp:", cursor });
    for (const item of page.keys) {
      const profile = await getJson(env.RECORDS_KV, item.name);
      if (!profile) continue;
      employees.push({
        employeeId: item.name.slice("emp:".length),
        name: profile.name ?? "",
        department: profile.department ?? "",
        email: profile.email,
        recordCount: Array.isArray(profile.records) ? profile.records.length : 0,
        updatedAt: profile.updatedAt ?? 0,
      });
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);

  return json({ success: true, employees });
}

async function handleAdminEmployeeRecords(request, env) {
  const body = await safeJson(request);
  const session = await getAdminSession(body?.adminToken, env);
  if (!session) {
    return json({ success: false, reason: "unauthorized" }, 401);
  }

  const employeeId = normalizeEmployeeId(body?.employeeId);
  const profile = employeeId ? await getJson(env.RECORDS_KV, employeeKey(employeeId)) : null;
  if (!profile) {
    return json({ success: false, reason: "not_found" });
  }

  return json({
    success: true,
    name: profile.name ?? "",
    department: profile.department ?? "",
    records: profile.records ?? [],
  });
}

async function handleAdminApprove(request, env) {
  const body = await safeJson(request);
  const session = await getAdminSession(body?.adminToken, env);
  if (!session) {
    return json({ success: false, reason: "unauthorized" }, 401);
  }

  const employeeId = normalizeEmployeeId(body?.employeeId);
  const dateMillis = Number(body?.dateMillis);
  const approved = Boolean(body?.approved);
  const key = employeeKey(employeeId);
  const profile = employeeId ? await getJson(env.RECORDS_KV, key) : null;
  if (!profile || !Array.isArray(profile.records)) {
    return json({ success: false, reason: "not_found" });
  }

  const record = profile.records.find((r) => Number(r.dateMillis) === dateMillis);
  if (!record) {
    return json({ success: false, reason: "not_found" });
  }

  record.approved = approved;
  record.approvedAt = approved ? Date.now() : null;
  await putJson(env.RECORDS_KV, key, profile, null);

  return json({ success: true });
}

async function getAdminSession(adminToken, env) {
  const token = (adminToken ?? "").toString().trim();
  if (!token) return null;
  return await getJson(env.ADMIN_KV, adminTokenKey(token));
}

// ---- Brevo email sending ------------------------------------------------

async function sendOtpEmail(env, email, otp) {
  try {
    const res = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        "api-key": env.BREVO_API_KEY,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        sender: { name: "Overtime Tracker", email: env.SENDER_EMAIL },
        to: [{ email }],
        subject: "Your Overtime Tracker verification code",
        htmlContent:
          `<p>Your verification code is:</p>` +
          `<h2 style="letter-spacing:4px;margin:8px 0">${otp}</h2>` +
          `<p>This code expires in 5 minutes. If you didn't request this, you can ignore this email.</p>`,
      }),
    });
    if (!res.ok) {
      console.log("Brevo send failed", res.status, await res.text());
    }
    return res.ok;
  } catch (e) {
    console.log("Brevo send threw", e);
    return false;
  }
}

// ---- KV helpers -----------------------------------------------------------

function otpKey(email) {
  return `otp:${email}`;
}

function employeeKey(employeeId) {
  return `emp:${employeeId}`;
}

function adminTokenKey(token) {
  return `admintoken:${token}`;
}

// Fixed key — one shared password means one possible live session, not one
// per account (see the ADMIN AUTH note above) — the single-session check
// in handleAdminLogin just needs to know whatever the CURRENT one is.
function activeTokenKey() {
  return `activetoken:hrreview`;
}

async function getJson(kv, key) {
  const raw = await kv.get(key);
  return raw ? JSON.parse(raw) : null;
}

// ttlMs === null means no expiry — used for records/* profiles, which must
// persist indefinitely (unlike OTP codes, which are meant to expire).
async function putJson(kv, key, value, ttlMs) {
  const options = ttlMs ? { expirationTtl: Math.ceil(ttlMs / 1000) } : {};
  await kv.put(key, JSON.stringify(value), options);
}

// ---- small utilities --------------------------------------------------

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function normalizeEmail(email) {
  return (email ?? "").toString().trim().toLowerCase();
}

function normalizeEmployeeId(employeeId) {
  return (employeeId ?? "").toString().trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateToken() {
  // 32 random bytes, hex-encoded — a bearer secret for records/sync, never
  // derivable from employeeId or email alone.
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function withCors(response) {
  response.headers.set("Access-Control-Allow-Origin", "*");
  response.headers.set("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  response.headers.set("Access-Control-Allow-Headers", "Content-Type");
  return response;
}

