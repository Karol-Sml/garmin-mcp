// Read-only client for the Garmin Connect Personal API.
//
// The personal API key (GARMIN_API_KEY secret) is exchanged for a bearer
// token that lives at most 24 h and cannot be refreshed, so we cache it in KV
// and simply request a new one when it expires or a call returns 401.

const TOKEN_URL =
  "https://personal.connectapi.garmin.com/personalapitoken-service/personal-api/personal-api-key/token";
const TOKEN_KV_KEY = "garmin:access-token";

// Only Garmin hosts are reachable through the generic tool, so a prompt
// injection cannot make the Worker send the bearer token anywhere else.
const ALLOWED_HOSTS = new Set([
  "personal.connectapi.garmin.com",
  "apis.garmin.com",
  "connectapi.garmin.com",
]);

type GarminEnv = { GARMIN_API_KEY?: string; OAUTH_KV: KVNamespace };

function jwtExpiry(token: string): number | null {
  try {
    const part = token.split(".")[1];
    if (!part) return null;
    const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
    const exp = JSON.parse(json).exp;
    return typeof exp === "number" ? exp : null;
  } catch {
    return null;
  }
}

async function requestToken(env: GarminEnv): Promise<string> {
  if (!env.GARMIN_API_KEY) throw new Error("GARMIN_API_KEY secret is not set on the Worker");
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: { Authorization: `ApiKey ${env.GARMIN_API_KEY}` },
  });
  const text = (await res.text()).trim();
  if (!res.ok) throw new Error(`Garmin token endpoint ${res.status}: ${text.slice(0, 300)}`);

  // The official client returns the JWT as plain text; accept JSON too.
  let token = text;
  if (text.startsWith("{")) {
    const parsed = JSON.parse(text);
    token = parsed.access_token ?? parsed.token ?? "";
  }
  token = token.replace(/^"|"$/g, "");
  if (!token) throw new Error("Garmin token endpoint returned no token");

  const exp = jwtExpiry(token);
  const ttl = exp ? Math.max(60, exp - Math.floor(Date.now() / 1000) - 300) : 20 * 3600;
  await env.OAUTH_KV.put(TOKEN_KV_KEY, token, { expirationTtl: ttl });
  return token;
}

async function getToken(env: GarminEnv, force = false): Promise<string> {
  if (!force) {
    const cached = await env.OAUTH_KV.get(TOKEN_KV_KEY);
    if (cached) return cached;
  }
  return requestToken(env);
}

export async function garminStatus(env: GarminEnv) {
  const configured = Boolean(env.GARMIN_API_KEY);
  if (!configured) return { keyConfigured: false };
  const token = await getToken(env, true);
  const exp = jwtExpiry(token);
  return {
    keyConfigured: true,
    tokenObtained: true,
    tokenExpires: exp ? new Date(exp * 1000).toISOString() : "unknown",
  };
}

export async function garminGet(env: GarminEnv, rawUrl: string, maxChars = 40000) {
  const url = new URL(rawUrl);
  if (url.protocol !== "https:" || !ALLOWED_HOSTS.has(url.hostname)) {
    throw new Error(`Host not allowed: ${url.hostname}. Allowed: ${[...ALLOWED_HOSTS].join(", ")}`);
  }

  const call = async (token: string) =>
    fetch(url.toString(), { method: "GET", headers: { Authorization: `Bearer ${token}` } });

  let res = await call(await getToken(env));
  if (res.status === 401) res = await call(await getToken(env, true));

  const contentType = res.headers.get("content-type") ?? "";
  if (/zip|octet-stream|fit/i.test(contentType)) {
    const bytes = (await res.arrayBuffer()).byteLength;
    return { status: res.status, contentType, note: `Binary response, ${bytes} bytes (not decoded)` };
  }

  const text = await res.text();
  const truncated = text.length > maxChars;
  return {
    status: res.status,
    contentType,
    truncated,
    totalChars: text.length,
    body: truncated ? text.slice(0, maxChars) : text,
  };
}
