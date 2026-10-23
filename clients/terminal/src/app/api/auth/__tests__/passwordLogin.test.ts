import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const verify = vi.hoisted(() => vi.fn());
const mint = vi.hoisted(() => vi.fn());
const setCookie = vi.hoisted(() => vi.fn());
vi.mock("../passwordAuth", () => ({ passwordAuthEnabled: () => true, verifyPasswordLogin: verify }));
vi.mock("../adminApi", () => ({ AUTH_COOKIE: "vexa-token", USER_INFO_COOKIE: "vexa-user-info", findOrCreateUserToken: mint }));
vi.mock("next/headers", () => ({ cookies: async () => ({ set: setCookie }) }));
import { POST } from "../login/route";
function request(body: unknown, origin = "https://vexa.example.com") {
  return new Request("https://vexa.example.com/api/auth/login", { method: "POST", headers: { "Content-Type": "application/json", Origin: origin }, body: JSON.stringify(body) }) as never;
}
beforeEach(() => {
  vi.stubEnv("NEXTAUTH_URL", "https://vexa.example.com");
  verify.mockReset().mockResolvedValue(false);
  mint.mockReset().mockResolvedValue({ ok: true, user: { id: 2, email: "kevin@example.com", name: "Kevin" }, token: "synthetic-token" });
  setCookie.mockReset();
});
afterEach(() => vi.unstubAllEnvs());
describe("password-mode login endpoint", () => {
  it("rejects passwordless debug sign-in even for test addresses", async () => {
    const res = await POST(request({ email: "test@example.com" }));
    expect(res.status).toBe(401);
    expect(mint).not.toHaveBeenCalled();
    expect(setCookie).not.toHaveBeenCalled();
  });
  it("issues a session only after correct password verification", async () => {
    verify.mockResolvedValue(true);
    const res = await POST(request({ email: "Kevin@example.com", password: "synthetic-fixture-password" }));
    expect(res.status).toBe(200);
    expect(verify).toHaveBeenCalledWith("kevin@example.com", "synthetic-fixture-password");
    expect(mint).toHaveBeenCalledWith("kevin@example.com");
    expect(setCookie).toHaveBeenCalledWith("vexa-token", "synthetic-token", expect.objectContaining({ httpOnly: true, secure: true, sameSite: "lax" }));
  });
  it("rate-limits repeated attempts without minting tokens", async () => {
    let res: Response | undefined;
    for (let n = 0; n < 11; n++) res = await POST(request({ email: "locked@example.com", password: "wrong" }));
    expect(res!.status).toBe(429);
    expect(mint).not.toHaveBeenCalled();
  });
  it("rejects a cross-origin login before password verification", async () => {
    const res = await POST(request({ email: "kevin@example.com", password: "synthetic-fixture-password" }, "https://evil.example"));
    expect(res.status).toBe(403);
    expect(verify).not.toHaveBeenCalled();
    expect(mint).not.toHaveBeenCalled();
  });
});
