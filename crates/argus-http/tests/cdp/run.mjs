import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const PORT = 9222;
const BASE = process.env.ARGUS_BASE ?? "http://localhost:8080";

const chrome = spawn(CHROME, [
  `--remote-debugging-port=${PORT}`,
  "--headless=new",
  "--no-first-run",
  "--no-default-browser-check",
  "--user-data-dir=/tmp/claude-501/cdp/profile",
  "about:blank",
], { stdio: "ignore" });

const cleanup = () => { try { chrome.kill(); } catch {} };
process.on("exit", cleanup);

let wsUrl = null;
for (let i = 0; i < 60; i++) {
  try {
    const r = await fetch(`http://127.0.0.1:${PORT}/json/version`);
    wsUrl = (await r.json()).webSocketDebuggerUrl;
    if (wsUrl) break;
  } catch {}
  await sleep(250);
}
if (!wsUrl) { console.error("chrome CDP acilmadi"); process.exit(1); }

const ws = new WebSocket(wsUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

let nextId = 1;
const pending = new Map();
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
  }
};
const send = (method, params = {}, sessionId) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });

const { targetId } = await send("Target.createTarget", { url: `${BASE}/.well-known/openid-configuration` });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });

await send("Page.enable", {}, sessionId);
await send("Runtime.enable", {}, sessionId);
await send("WebAuthn.enable", {}, sessionId);

const { authenticatorId } = await send("WebAuthn.addVirtualAuthenticator", {
  options: {
    protocol: "ctap2",
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  },
}, sessionId);
console.log("sanal authenticator:", authenticatorId);

await sleep(500);

const script = String.raw`
(async () => {
  const b64uToBuf = (s) => {
    const p = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(p + "=".repeat((4 - p.length % 4) % 4));
    return Uint8Array.from(bin, c => c.charCodeAt(0)).buffer;
  };
  const bufToB64u = (b) =>
    btoa(String.fromCharCode(...new Uint8Array(b)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const ident = "cdp-" + Math.random().toString(36).slice(2) + "@example.com";
  const pass  = "a strong enough passphrase";
  const steps = {};

  let r = await fetch("/register", { method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ identifier: ident, password: pass }) });
  steps.register = r.status;

  r = await fetch("/login", { method: "POST", credentials: "include",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ identifier: ident, password: pass }) });
  steps.login = r.status;

  r = await fetch("/webauthn/register/start", { method: "POST", credentials: "include" });
  steps.register_start = r.status;
  const reg = await r.json();

  const pk = reg.publicKey;
  pk.challenge = b64uToBuf(pk.challenge);
  pk.user.id = b64uToBuf(pk.user.id);
  if (pk.excludeCredentials) pk.excludeCredentials.forEach(c => c.id = b64uToBuf(c.id));

  const cred = await navigator.credentials.create({ publicKey: pk });
  steps.created = !!cred;

  r = await fetch("/webauthn/register/finish", { method: "POST", credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ceremony_id: reg.ceremony_id, credential: {
      id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type,
      response: {
        attestationObject: bufToB64u(cred.response.attestationObject),
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      },
      extensions: {},
    }}) });
  steps.register_finish = r.status;
  if (r.status >= 400) steps.register_finish_body = await r.text();

  r = await fetch("/webauthn/authenticate/start", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: ident }) });
  steps.auth_start = r.status;
  const auth = await r.json();
  const apk = auth.publicKey;
  apk.challenge = b64uToBuf(apk.challenge);
  if (apk.allowCredentials) apk.allowCredentials.forEach(c => c.id = b64uToBuf(c.id));
  steps.allow_credentials = (apk.allowCredentials || []).length;

  const asrt = await navigator.credentials.get({ publicKey: apk });
  steps.asserted = !!asrt;

  r = await fetch("/webauthn/authenticate/finish", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ceremony_id: auth.ceremony_id, credential: {
      id: asrt.id, rawId: bufToB64u(asrt.rawId), type: asrt.type,
      response: {
        authenticatorData: bufToB64u(asrt.response.authenticatorData),
        clientDataJSON: bufToB64u(asrt.response.clientDataJSON),
        signature: bufToB64u(asrt.response.signature),
        userHandle: asrt.response.userHandle ? bufToB64u(asrt.response.userHandle) : null,
      },
      extensions: {},
    }}) });
  steps.auth_finish = r.status;
  if (r.status >= 400) steps.auth_finish_body = await r.text();

  const replay = await fetch("/webauthn/authenticate/finish", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ceremony_id: auth.ceremony_id, credential: {
      id: asrt.id, rawId: bufToB64u(asrt.rawId), type: asrt.type,
      response: {
        authenticatorData: bufToB64u(asrt.response.authenticatorData),
        clientDataJSON: bufToB64u(asrt.response.clientDataJSON),
        signature: bufToB64u(asrt.response.signature),
        userHandle: asrt.response.userHandle ? bufToB64u(asrt.response.userHandle) : null,
      },
      extensions: {},
    }}) });
  steps.replayed_ceremony = replay.status;
  steps.replayed_error = (await replay.json()).error;

  const unknown = await fetch("/webauthn/authenticate/start", { method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: "nobody-" + Math.random() + "@example.com" }) });
  const unknownBody = await unknown.json();
  steps.unknown_account_challenge = unknown.status;
  steps.unknown_account_allow = (unknownBody.publicKey.allowCredentials || []).length;

  return JSON.stringify(steps);
})()
`;

const result = await send("Runtime.evaluate", {
  expression: script, awaitPromise: true, returnByValue: true,
}, sessionId);

if (result.exceptionDetails) {
  console.error("sayfa hatasi:", JSON.stringify(result.exceptionDetails).slice(0, 400));
  process.exit(1);
}
const steps = JSON.parse(result.result.value);
console.log("adimlar:", JSON.stringify(steps));

const expected = {
  register: 201, login: 200, register_start: 200, created: true,
  register_finish: 204, auth_start: 200, allow_credentials: 1,
  asserted: true, auth_finish: 200,
  replayed_ceremony: 400,
  replayed_error: "the ceremony is unknown or has expired",
  unknown_account_challenge: 200, unknown_account_allow: 0,
};

let failed = false;
for (const [k, want] of Object.entries(expected)) {
  if (steps[k] !== want) {
    console.error(`FAIL ${k}: beklenen ${want}, gelen ${JSON.stringify(steps[k])}`);
    failed = true;
  }
}

if (failed) process.exit(1);
console.log("CDP Virtual Authenticator: RP akisi yesil (tekrar ve bilinmeyen hesap kontrolleri dahil)");
process.exit(0);
