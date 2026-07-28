# SS-Sethi push sender (Cloudflare Worker)

Sends FCM push notifications when app events fire. Free, no credit card.

## What you need first
- A free [Cloudflare account](https://dash.cloudflare.com/sign-up) (no card).
- A **Firebase service account key**:
  Firebase console → ⚙ Project settings → **Service accounts** → **Generate new private key** → downloads a `.json` file. Keep it safe — it's a secret.

## Deploy (dashboard method — easiest, no CLI)
1. Cloudflare dashboard → **Workers & Pages** → **Create** → **Create Worker**. Name it e.g. `ss-sethi-push`. Click **Deploy** (creates a starter), then **Edit code**.
2. Delete the starter code, paste all of [`worker.js`](./worker.js), click **Deploy**.
3. Add the secret: Worker → **Settings** → **Variables and Secrets** → **Add** → type **Secret**:
   - Name: `FIREBASE_SERVICE_ACCOUNT`
   - Value: paste the **entire contents** of the service-account `.json` file
   - Save / Deploy.
4. Copy the Worker URL (e.g. `https://ss-sethi-push.<your-subdomain>.workers.dev`) and send it to me. I'll set it as `VITE_NOTIFY_URL` and redeploy the app — notifications go live.

## Deploy (CLI method — optional)
```bash
cd cloudflare-worker
npx wrangler deploy
npx wrangler secret put FIREBASE_SERVICE_ACCOUNT   # paste the JSON when prompted
```

## Test it
```bash
curl -X POST https://ss-sethi-push.<subdomain>.workers.dev \
  -H "Content-Type: application/json" \
  -d '{"targetRole":"manufacturing","title":"Test","body":"Hello from the worker"}'
```
Expect `{"ok":true,"sent":N,...}`. `sent:0` just means no devices have registered for that role yet (log into the app on a phone first and allow notifications).

## How it works
`{targetRole,title,body,url}` → the Worker mints a Google OAuth token from the
service account → queries Firestore `pushSubscriptions` for that role's device
tokens → sends each an FCM v1 message. Dead tokens are pruned automatically.
