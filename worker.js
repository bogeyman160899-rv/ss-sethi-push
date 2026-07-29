/**
 * SS-Sethi push sender — Cloudflare Worker (raw Web Push / VAPID).
 *
 * Receives { targetRole, title, body, url }, reads that role's Web Push
 * subscriptions from Firestore, encrypts the payload (RFC 8291 aes128gcm),
 * signs a VAPID JWT (RFC 8292), and POSTs directly to each push endpoint.
 * This is the native web-push path that iOS PWAs actually deliver.
 *
 * Secrets/config:
 *   env.VAPID_PRIVATE  — VAPID private key (base64url, 32-byte scalar)  [secret]
 *   VAPID_PUBLIC       — VAPID public key (base64url, 65-byte point)    [below]
 *   FIREBASE_API_KEY   — public web API key, for unauthenticated Firestore reads
 */

const VAPID_PUBLIC = "BJ2FD6iK08kqtiBD__CoKluoJCGMzNZg-GipFtv_0I7O0KgJyAyAtA8Ch1cjJf7oACjYrxPs7LMcsnbGB5wGTXg";
const VAPID_SUBJECT = "mailto:chadorkart@gmail.com";
const PROJECT_ID = "ss-sethi-orders-v2";
const FIREBASE_API_KEY = "AIzaSyCHzqGKgP9nyPrxRRqdaTFhPTqSbftU8u4";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};
const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json" } });

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (request.method !== "POST") return json({ error: "POST only" }, 405);
    if (!env.VAPID_PRIVATE) return json({ error: "VAPID_PRIVATE secret missing" }, 500);

    let payload;
    try { payload = await request.json(); } catch { return json({ error: "Bad JSON" }, 400); }
    const { targetRole, title, body, url } = payload || {};
    if (!targetRole || !title || !body) return json({ error: "targetRole, title, body required" }, 400);

    let subs;
    try { subs = await subsForRole(targetRole); }
    catch (e) { return json({ error: "firestore read failed: " + e.message }, 500); }
    if (!subs.length) return json({ ok: true, sent: 0, note: "no devices for role " + targetRole });

    const message = JSON.stringify({ title, body, url: url || "/" });
    let sent = 0;
    const errors = [];
    for (const s of subs) {
      try {
        const res = await sendWebPush(s, message, env.VAPID_PRIVATE);
        if (res.ok || res.status === 201) { sent++; continue; }
        errors.push({ status: res.status });
        if (res.status === 404 || res.status === 410) await deleteDoc(s.name).catch(() => {});
      } catch (e) { errors.push({ error: String(e.message || e) }); }
    }
    return json({ ok: true, sent, of: subs.length, errors: errors.length ? errors : undefined });
  },
};

// ── Firestore REST (unauthenticated; rules are open) ─────────
async function subsForRole(role) {
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents:runQuery?key=${FIREBASE_API_KEY}`,
    { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ structuredQuery: {
        from: [{ collectionId: "pushSubscriptions" }],
        where: { fieldFilter: { field: { fieldPath: "role" }, op: "EQUAL", value: { stringValue: role } } },
      } }) }
  );
  if (!res.ok) throw new Error(await res.text());
  const rows = await res.json();
  return (Array.isArray(rows) ? rows : [])
    .filter((r) => r.document?.fields?.endpoint?.stringValue)
    .map((r) => ({
      name: r.document.name,
      endpoint: r.document.fields.endpoint.stringValue,
      p256dh: r.document.fields.p256dh.stringValue,
      auth: r.document.fields.auth.stringValue,
    }));
}
async function deleteDoc(name) {
  await fetch(`https://firestore.googleapis.com/v1/${name}?key=${FIREBASE_API_KEY}`, { method: "DELETE" });
}

// ── Web Push send: encrypt + VAPID, POST to endpoint ─────────
async function sendWebPush(sub, plaintext, vapidPrivateB64) {
  const bodyBytes = await encrypt(plaintext, sub.p256dh, sub.auth);
  const auth = await vapidAuth(new URL(sub.endpoint).origin, vapidPrivateB64);
  return fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: auth,
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "86400",
      Urgency: "high",
    },
    body: bodyBytes,
  });
}

// RFC 8291 aes128gcm content encryption
async function encrypt(plaintext, p256dhB64, authB64) {
  const uaPublic = b64uToBytes(p256dhB64);   // 65 bytes
  const authSecret = b64uToBytes(authB64);   // 16 bytes

  const asKeys = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", asKeys.publicKey)); // 65 bytes
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, asKeys.privateKey, 256));

  // PRK for the key: HKDF(salt=auth, ikm=ecdh, info="WebPush: info\0"||ua||as, 32)
  const keyInfo = concat(utf8("WebPush: info"), U8([0]), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, ecdh, keyInfo, 32);

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, concat(utf8("Content-Encoding: aes128gcm"), U8([0])), 16);
  const nonce = await hkdf(salt, ikm, concat(utf8("Content-Encoding: nonce"), U8([0])), 12);

  const padded = concat(utf8(plaintext), U8([2])); // 0x02 = last record delimiter
  const cekKey = await crypto.subtle.importKey("raw", cek, { name: "AES-GCM" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, cekKey, padded));

  // header: salt(16) | rs(4=4096) | idlen(1=65) | as_public(65) | ciphertext
  return concat(salt, U8([0, 0, 0x10, 0]), U8([asPublic.length]), asPublic, ct);
}

async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, { name: "HKDF" }, false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

// RFC 8292 VAPID Authorization header
async function vapidAuth(audience, vapidPrivateB64) {
  const header = { typ: "JWT", alg: "ES256" };
  const payloadObj = { aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: VAPID_SUBJECT };
  const unsigned = b64u(utf8(JSON.stringify(header))) + "." + b64u(utf8(JSON.stringify(payloadObj)));

  const pub = b64uToBytes(VAPID_PUBLIC); // [0x04, x(32), y(32)]
  const jwk = { kty: "EC", crv: "P-256", ext: true,
    x: b64u(pub.slice(1, 33)), y: b64u(pub.slice(33, 65)), d: vapidPrivateB64.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_") };
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, utf8(unsigned)));
  const jwt = unsigned + "." + b64u(sig);
  return `vapid t=${jwt}, k=${VAPID_PUBLIC}`;
}

// ── byte helpers ──
function U8(a) { return new Uint8Array(a); }
function utf8(s) { return new TextEncoder().encode(s); }
function concat(...arrs) {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let o = 0; for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
function b64u(bytes) {
  let s = ""; for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64uToBytes(b64) {
  const pad = "=".repeat((4 - (b64.length % 4)) % 4);
  const s = atob((b64 + pad).replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
