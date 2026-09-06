// Overtime Tracker OTP backend — Cloudflare Workers + Brevo (email) + Workers KV (storage).
//
// Why this instead of the old Render backend: Render's free web services sleep
// after 15 minutes of inactivity and take 30-60s to wake up, which was longer
// than the app's 15s timeout — that's what caused "Couldn't reach the server".
// Cloudflare Workers is serverless at the edge and never sleeps, so this
// backend responds in milliseconds even after long idle periods.
//
// API contract (unchanged from before — the Android app needs no code changes
// beyond updating ApiClient.BASE_URL):
//   POST /otp/send   { "email": "..." }              -> { "success": bool, "reason": "invalid_email"|"cooldown"|"email_send_failed"|null }
//   POST /otp/verify { "email": "...", "otp": "..." } -> { "success": bool, "reason": "incorrect"|"expired"|"too_many_attempts"|"not_requested"|null }

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

    if (url.pathname === "/" && request.method === "GET") {
      return withCors(json({ success: true, message: "Overtime Tracker OTP service is running." }));
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
  const existing = await getRecord(env, key);

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
  await putRecord(env, key, record, OTP_TTL_MS + 60_000);

  return json({ success: true });
}

async function handleVerify(request, env) {
  const body = await safeJson(request);
  const email = normalizeEmail(body?.email);
  const otp = (body?.otp ?? "").toString().trim();

  const key = otpKey(email);
  const record = await getRecord(env, key);
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
    await putRecord(env, key, record, Math.max(1, record.expiresAt - now) + 60_000);
    return json({ success: false, reason: "incorrect" });
  }

  await env.OTP_KV.delete(key);
  return json({ success: true });
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

async function getRecord(env, key) {
  const raw = await env.OTP_KV.get(key);
  return raw ? JSON.parse(raw) : null;
}

async function putRecord(env, key, record, ttlMs) {
  await env.OTP_KV.put(key, JSON.stringify(record), {
    expirationTtl: Math.ceil(ttlMs / 1000),
  });
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

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
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
      
