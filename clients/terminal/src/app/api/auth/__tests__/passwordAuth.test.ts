// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scryptSync } from "node:crypto";
import { verifyPasswordLogin, passwordAuthEnabled } from "../passwordAuth";

let dir: string;
// Public synthetic fixture, never an operator credential.
const password = "Synthetic-fixture-only-123!";
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), "vexa-password-test-"));
  vi.stubEnv("VEXA_PASSWORD_AUTH_FILE", join(dir, "users.json"));
  const salt = "0123456789abcdef0123456789abcdef";
  const hash = scryptSync(password, salt, 64, { N: 32768, r: 8, p: 3, maxmem: 67108864 }).toString("hex");
  await writeFile(join(dir, "users.json"), JSON.stringify({ users: [{ email: "kevin@example.com", passwordHash: `scrypt$32768$8$3$${salt}$${hash}` }] }));
});
afterEach(async () => { vi.unstubAllEnvs(); await rm(dir, { recursive: true, force: true }); });
describe("local email/password authentication", () => {
  it("requires the stored password for an explicitly provisioned email", async () => {
    expect(passwordAuthEnabled()).toBe(true);
    expect(await verifyPasswordLogin("kevin@example.com", password)).toBe(true);
    expect(await verifyPasswordLogin("kevin@example.com", "wrong-password")).toBe(false);
    expect(await verifyPasswordLogin("stranger@example.com", password)).toBe(false);
  });
  it("fails closed if the credential file is missing or malformed", async () => {
    await rm(join(dir, "users.json"));
    expect(await verifyPasswordLogin("kevin@example.com", password)).toBe(false);
    await writeFile(join(dir, "users.json"), "not-json");
    expect(await verifyPasswordLogin("kevin@example.com", password)).toBe(false);
  });
  it("bounds password size and never accepts empty credentials", async () => {
    expect(await verifyPasswordLogin("kevin@example.com", "")).toBe(false);
    expect(await verifyPasswordLogin("kevin@example.com", "a".repeat(1025))).toBe(false);
    expect(await verifyPasswordLogin("kevin@example.com", null)).toBe(false);
  });
});
