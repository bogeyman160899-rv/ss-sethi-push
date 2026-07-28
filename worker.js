/**
 * SS-Sethi push sender — Cloudflare Worker.
 *
 * Receives { targetRole, title, body, url } from the app, looks up that role's
 * FCM tokens in Firestore, and sends each a push via the FCM HTTP v1 API.
 *
 * Auth: a Firebase service account (stored as the Worker secret
 * FIREBASE_SERVICE_ACCOUNT — the full JSON) is used to mint a short-lived
 * Google OAuth token, which authorises both Firestore reads and FCM sends.
 *
 * No secrets live in this file — the service account is injected via env.
 */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (request.method !== "POST") return json({ error: "POST only" }, 405);

    let sa;
    try { sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT); }
    catch { return json({ error: "FIREBASE_SERVICE_ACCOUNT secret missing or invalid" }, 500); }

    let payload;
    try { payload = await request.json(); } catch { return json({ error: "Bad JSON" }, 400); }
    const { targetRole, title, body, url } = payload || {};
    if (!targetRole || !title || !body) return json({ error: "targetRole, title, body required" }, 400);

    const projectId = sa.project_id;
    let token;
    try { token = await getAccessToken(sa); }
    catch (e) { return json({ error: "auth failed: " + e.message }, 500); }

    // 1) Look up the role's registered FCM tokens from Firestore.
    let tokens = [];
    try { tokens = await tokensForRole(projectId, token, targetRole); }
    catch (e) { return json({ error: "firestore query failed: " + e.message }, 500); }
    if (!tokens.length) return json({ ok: true, sent: 0, note: "no devices for role " + targetRole });

    // 2) Send to each device; prune tokens FCM reports as dead.
    let sent = 0;
    const errors = [];
    for (const t of tokens) {
      const res = await fetch(`https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          message: {
            token: t.token,
            notification: { title, body },
            webpush: { fcm_options: { link: url || "/" }, notification: { icon: "/icon-192.png" } },
          },
        }),
      });
      if (res.ok) { sent++; continue; }
      const err = await res.json().catch(() => ({}));
      const code = err?.error?.details?.[0]?.errorCode || err?.error?.status;
      errors.push({ code, status: res.status });
      if (code === "UNREGISTERED" || res.status === 404) await deleteDoc(projectId, token, t.name).catch(() => {});
    }
    return json({ ok: true, sent, of: tokens.length, errors: errors.length ? errors : undefined });
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json" } });
}

// ── Firestore REST: read/delete pushSubscriptions ────────────
async function tokensForRole(projectId, accessToken, role) {
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents:runQuery`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: "pushSubscriptions" }],
          where: { fieldFilter: { field: { fieldPath: "role" }, op: "EQUAL", value: { stringValue: role } } },
        },
      }),
    }
  );
  if (!res.ok) throw new Error(await res.text());
  const rows = await res.json();
  return (Array.isArray(rows) ? rows : [])
    .filter((r) => r.document?.fields?.token?.stringValue)
    .map((r) => ({ token: r.document.fields.token.stringValue, name: r.document.name }));
}

async function deleteDoc(projectId, accessToken, docName) {
  // docName is the full resource path returned by runQuery.
  await fetch(`https://firestore.googleapis.com/v1/${docName}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${accessToken}` },
  });
}

// ── Google OAuth2: service-account JWT → access token ────────
async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  const claim = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging https://www.googleapis.com/auth/datastore",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const header = { alg: "RS256", typ: "JWT" };
  const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const unsigned = `${enc(header)}.${enc(claim)}`;

  const key = await crypto.subtle.importKey(
    "pkcs8", pemToBuf(sa.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(unsigned));
  const jwt = `${unsigned}.${b64url(new Uint8Array(sig))}`;

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) throw new Error(await res.text());
  return (await res.json()).access_token;
}

function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function pemToBuf(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
