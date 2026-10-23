/** Server-only, fail-closed credential verification. Only salted scrypt hashes live on disk.
 * An explicit file enables password mode; a missing/bad file never restores debug login.
 * Provision users out of band: there is deliberately no public registration endpoint.
 */
import { readFile } from "node:fs/promises";
import { scrypt, timingSafeEqual } from "node:crypto";

export function passwordAuthEnabled(): boolean {
  return !!process.env.VEXA_PASSWORD_AUTH_FILE;
}

const DUMMY_SALT = "00000000000000000000000000000000";
const DUMMY_HASH = "00".repeat(64);

export async function verifyPasswordLogin(email: string, password: unknown): Promise<boolean> {
  if (typeof password !== "string" || password.length < 1 || Buffer.byteLength(password) > 1024) return false;
  let stored: string | undefined;
  try {
    const file = process.env.VEXA_PASSWORD_AUTH_FILE;
    if (!file) return false;
    const data = JSON.parse(await readFile(file, "utf8")) as { users?: { email?: string; passwordHash?: string }[] };
    stored = data.users?.find((u) => u.email === email)?.passwordHash;
  } catch { return false; }
  const parts = (stored || `scrypt$32768$8$3$${DUMMY_SALT}$${DUMMY_HASH}`).split("$");
  // Pin work factors and encodings, rather than executing arbitrary expensive settings from a file.
  if (parts.length !== 6 || parts[0] !== "scrypt" || parts[1] !== "32768" || parts[2] !== "8" || parts[3] !== "3" || !/^[a-f0-9]{32}$/.test(parts[4]) || !/^[a-f0-9]{128}$/.test(parts[5])) return false;
  const actual = await new Promise<Buffer>((resolve, reject) => {
    scrypt(password, parts[4], 64, { N: 32768, r: 8, p: 3, maxmem: 67108864 }, (err, key) => err ? reject(err) : resolve(key));
  });
  return timingSafeEqual(actual, Buffer.from(parts[5], "hex")) && !!stored;
}
