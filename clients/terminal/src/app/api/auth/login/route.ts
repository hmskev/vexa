/** Direct email login — no SMTP, no magic link. POST {email} → find-or-create the user at admin-api,
 *  mint an APIToken (scopes bot,tx,browser), set the httpOnly `vexa-token` + `vexa-user-info` cookies.
 *
 *  Mirrors the dashboard's VEXA_ALLOW_DIRECT_LOGIN branch (without importing it). No email is ever sent.
 *  Must never be cached — a cached response would pin one identity for every subsequent login.
 */
import { NextResponse, type NextRequest } from "next/server";
import { cookies } from "next/headers";
import { AUTH_COOKIE, USER_INFO_COOKIE, findOrCreateUserToken } from "../adminApi";
import { passwordAuthEnabled, verifyPasswordLogin } from "../passwordAuth";

export const dynamic = "force-dynamic";
export const fetchCache = "force-no-store";

const NO_STORE = { "Cache-Control": "no-store, no-cache, must-revalidate" } as const;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
// Single-process self-hosted deployment. Bounded, expiring counters; no proxy-header trust.
const attempts = new Map<string, { count: number; until: number }>();
let globalWindow = { count: 0, until: 0 };
function loginLimited(email: string): boolean {
  const now = Date.now();
  for (const [key, value] of attempts) if (value.until <= now) attempts.delete(key);
  if (globalWindow.until <= now) globalWindow = { count: 0, until: now + 15 * 60 * 1000 };
  if (++globalWindow.count > 100) return true;
  const item = attempts.get(email) || { count: 0, until: now + 15 * 60 * 1000 };
  attempts.set(email, item);
  return ++item.count > 10;
}

function isSecureRequest(): boolean {
  return (
    (process.env.TERMINAL_URL || "").startsWith("https://") ||
    (process.env.NEXTAUTH_URL || "").startsWith("https://") ||
    false
  );
}

export async function POST(request: NextRequest) {
  const passwordMode = passwordAuthEnabled();
  if (passwordMode && (!process.env.NEXTAUTH_URL || request.headers.get("origin") !== new URL(process.env.NEXTAUTH_URL).origin || !request.headers.get("content-type")?.startsWith("application/json"))) {
    return NextResponse.json({ error: "Invalid login origin" }, { status: 403, headers: NO_STORE });
  }
  let email: unknown;
  let password: unknown;
  try {
    ({ email, password } = await request.json());
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400, headers: NO_STORE });
  }

  if (typeof email !== "string" || !email.trim()) {
    return NextResponse.json({ error: "Email is required" }, { status: 400, headers: NO_STORE });
  }
  const normalized = email.trim().toLowerCase();
  if (!EMAIL_RE.test(normalized)) {
    return NextResponse.json({ error: "Invalid email format" }, { status: 400, headers: NO_STORE });
  }
  // Direct email login is a DEBUG path only — real sign-in goes through Google/Microsoft OAuth
  // (api/auth/[...nextauth]). Restrict it to test accounts so it can't be used as a password-less bypass.
  if (passwordMode) {
    if (loginLimited(normalized)) {
      return NextResponse.json({ error: "Too many sign-in attempts. Try again in 15 minutes." }, { status: 429, headers: { ...NO_STORE, "Retry-After": "900" } });
    }
    if (!(await verifyPasswordLogin(normalized, password))) {
      return NextResponse.json({ error: "Invalid email or password" }, { status: 401, headers: NO_STORE });
    }
  } else if (!normalized.includes("test")) {
    return NextResponse.json(
      { error: "Direct email login is for test accounts only — use Google or Microsoft sign-in." },
      { status: 403, headers: NO_STORE },
    );
  }

  const result = await findOrCreateUserToken(normalized);
  if (!result.ok) {
    return NextResponse.json({ error: result.error }, { status: result.status || 500, headers: NO_STORE });
  }

  const { user, token } = result;
  const secure = isSecureRequest();
  const cookieStore = await cookies();
  const opts = { httpOnly: true, secure, sameSite: "lax" as const, maxAge: 60 * 60 * 24 * (passwordMode ? 7 : 30), path: "/" };
  cookieStore.set(AUTH_COOKIE, token, opts);
  cookieStore.set(USER_INFO_COOKIE, JSON.stringify({ email: user.email, name: user.name || user.email.split("@")[0] }), opts);

  return NextResponse.json(
    { success: true, user: { id: user.id, email: user.email, name: user.name ?? user.email } },
    { headers: NO_STORE },
  );
}
