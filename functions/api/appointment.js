export async function onRequestPost({ request, env }) {
  try {
    const form = await request.formData();

    // Honeypot (bots fill this)
    if ((form.get("company") || "").toString().trim()) {
      return json({ ok: true });
    }

    const name = form.get("name")?.toString().trim();
    const email = form.get("email")?.toString().trim();
    const phone = form.get("phone")?.toString().trim();
    const message = form.get("message")?.toString().trim();
    const token = form.get("cf-turnstile-response")?.toString().trim();

    if (!name || !email || !message) {
      return json({ error: "Missing required fields." }, 400);
    }

    // Turnstile validation
    if (env.TURNSTILE_SECRET_KEY) {
      if (!token) return json({ error: "Spam check missing." }, 400);

      const verify = await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        {
          method: "POST",
          body: new URLSearchParams({
            secret: env.TURNSTILE_SECRET_KEY,
            response: token,
            remoteip: request.headers.get("CF-Connecting-IP") || ""
          })
        }
      ).then(r => r.json());

      if (!verify.success) {
        return json({ error: "Spam check failed." }, 403);
      }
    }

    // Send email
    const resend = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: env.FROM_EMAIL,
        to: env.TO_EMAIL,
        subject: `Appointment request — ${name}`,
        reply_to: email,
        text: `Name: ${name}
Email: ${email}
Phone: ${phone || "(not provided)"}

Message:
${message}`
      })
    });

    if (!resend.ok) {
      return json({ error: "Email failed." }, 502);
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
