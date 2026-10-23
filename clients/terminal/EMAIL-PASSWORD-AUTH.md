# Self-hosted email/password sign-in

Set `VEXA_PASSWORD_AUTH_FILE=/var/lib/vexa-auth/users.json` and mount a host-owned directory at `/var/lib/vexa-auth`. Set `NEXTAUTH_URL` to the exact public HTTPS origin. Only a provisioned email with a matching password hash can sign in. There is no public registration and no SMTP/OAuth dependency.

The credential file is read on each login, so an operator can rotate hashes atomically without rebuilding the image. Keep the directory mode 700 and JSON mode 600; never commit either passwords or hashes. Back up this file with the deployment's protected configuration. Example shape (placeholders are not valid credentials):

```json
{"users":[{"email":"owner@example.com","passwordHash":"scrypt$32768$8$3$<32 lowercase hex salt>$<128 lowercase hex derived key>"}]}
```

The salt is passed to Node/Python scrypt as the 32-character ASCII hex string, not decoded salt bytes. Parameters: N=32768, r=8, p=3, key length 64, maxmem=67108864. Generate a fresh random 16-byte salt for every password. Use a password manager to generate long random passwords; keep initial delivery private. Provision or rename the matching identity in admin-api/database before login when preserving an existing user's data. Meetings remain attached to their numeric user ID, not the email string.

When password mode is configured:
- Missing/malformed credential files fail closed; the debug restriction is not used.
- Passwordless test-email login is rejected.
- Login POSTs require the configured exact Origin and application/json.
- Password inputs are bounded to 1024 UTF-8 bytes.
- Account attempts are capped at 10 per 15 minutes; total login work is capped at 100 attempts per 15 minutes. Counters are process-local: deploy a single terminal replica and retain edge rate-limiting for multi-replica installations.
- API and WebSocket proxies never fall back to the shared environment bot key for signed-out callers.
- The session probe validates the upstream token and uses its verified email instead of trusting a display cookie.
- Newly minted login tokens and browser cookies expire after seven days.

For transition from debug mode, set fresh `VEXA_AUTH_COOKIE_NAME` and `VEXA_USER_INFO_COOKIE_NAME` values in the terminal environment, and revoke tokens issued to obsolete test users. Preserve programmatic keys belonging to active integrations. Keep OAuth provider credentials unset for email/password-only deployments.

Rollback: restore the previous terminal image and compose configuration. Preserve the credential file, database backup, and renamed user ID. Do not reset the database or move meeting ownership just to repair login.
