import { afterEach, expect, it, vi } from "vitest";
vi.mock("next/headers", () => ({ cookies: async () => ({ get: () => undefined }) }));
import { resolveApiKey } from "../proxyAuth";
afterEach(() => vi.unstubAllEnvs());
it("password deployments never expose the shared bot key to signed-out callers", async () => {
  vi.stubEnv("VEXA_PASSWORD_AUTH_FILE", "/state/users.json");
  vi.stubEnv("VEXA_BOT_API_KEY", "synthetic-shared-key");
  vi.stubEnv("VEXA_API_KEY", "synthetic-env-key");
  expect(await resolveApiKey()).toBe("");
});
