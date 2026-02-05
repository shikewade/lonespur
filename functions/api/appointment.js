export async function onRequestPost({ request, env }) {
  try {
    const form = await request.formData();

    // Honeypot (bots often fill hidden fields)
    if ((form.get("company") || "").toString().trim()) {
      return json({ ok: true });
    }

    // Read fields
    const name = (form.get("name") || "").toString().trim();
    const email = (form.get("email") || "").toString().trim();
    const phone = (form.get("phone") || "").toString().trim();
    const message = (form.get("message") || "").toString().trim();
    const token = (form.get("cf-turnstile-response") || "").toString().trim();

    // NEW: request type from dropdown
    const requestType = (form.get("request_type") || "").toString().trim();
    const allowedTypes = ["Sales", "Information", "Appointment"];

    // Validate required fields
    if (!name || !email || !message) {
      return json({ error: "Missing required fields." }, 400);
    }

    // NEW: validate request type
    if (!allowedTypes.includes(requestType)) {
      return json({ error: "Invalid request type." }, 400);
    }

    // Turnstile verification (recommended)
    if (env.TURNSTILE_SECRET_KEY) {
      if (!token) return json({ error: "Spam check missing." }, 400);

      const verify = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
        method: "POST",
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token,
          remoteip: request.headers.get("CF-Connecting-IP") || ""
        })
      }).then(r => r.json());

      if (!verify.success) {
        return json({ error: "Spam check failed." }, 403);
      }
    }

    // ---- KV BACKUP (best-effort; won't block email) ----
    const submittedAt = new Date().toISOString();
    const id = crypto.randomUUID();

    const kvRecord = {
      id,
      submittedAt,
      requestType, // NEW
      name,
      email,
      phone,
      message,
      ip: request.headers.get("CF-Connecting-IP") || null,
      userAgent: request.headers.get("User-Agent") || null,
    };

    if (env.APPOINTMENTS_KV) {
      try {
        const key = `${submittedAt}_${id}`;
        await env.APPOINTMENTS_KV.put(key, JSON.stringify(kvRecord), {
          // Optional: auto-expire after 180 days
          expirationTtl: 60 * 60 * 24 * 180
        });
      } catch (_) {
        // Ignore KV errors so form still works
      }
    }

    // ---- EMAIL via Resend ----
    if (!env.RESEND_API_KEY) return json({ error: "Missing RESEND_API_KEY." }, 500);
    if (!env.FROM_EMAIL) return json({ error: "Missing FROM_EMAIL." }, 500);
    if (!env.TO_EMAIL) return json({ error: "Missing TO_EMAIL." }, 500);

    const subject = `[${requestType}] Request — ${name}`;
    const text =
`New ${requestType} request

Type: ${requestType}
Name: ${name}
Email: ${email}
Phone: ${phone || "(not provided)"}

Message:
${message}

Backup ID: ${id}
Submitted: ${submittedAt}
`;

    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: env.TO_EMAIL,
        subject,
        reply_to: email,
        text
      })
    });

    if (!resendRes.ok) {
      return json({ error: "Email failed. Please try again later." }, 502);
    }

    return json({ ok: true });
  } catch {
    return json({ error: "Bad request." }, 400);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

