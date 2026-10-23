import { afterEach, expect, it, vi } from "vitest";
const validate = vi.hoisted(() => vi.fn());
vi.mock("next/headers", () => ({ cookies: async () => ({ get: (key: string) => ({ value: key === "vexa-token" ? "synthetic-expired" : JSON.stringify({ email: "forged@example.com" }) }) }) }));
vi.mock("../adminApi", () => ({ AUTH_COOKIE: "vexa-token", USER_INFO_COOKIE: "vexa-user-info", validateAuthToken: validate }));
import { GET } from "../me/route";
afterEach(() => vi.unstubAllEnvs());
it("password mode checks session validity instead of trusting cookie presence", async () => {
  vi.stubEnv("VEXA_PASSWORD_AUTH_FILE", "/state/users.json");
  validate.mockResolvedValue({ ok: false, status: 401, error: "Not authenticated" });
  const res = await GET();
  expect(res.status).toBe(401);
});
it("password mode returns verified identity, not the display cookie", async () => {
  vi.stubEnv("VEXA_PASSWORD_AUTH_FILE", "/state/users.json");
  validate.mockResolvedValue({ ok: true, userId: 2, email: "kevin@example.com", isAdmin: true });
  const res = await GET();
  expect((await res.json()).user.email).toBe("kevin@example.com");
});
