# Mandatory two-factor authentication

Every interactive account, including Django superusers and every SOC role, must
complete authenticator enrollment before accessing the application. There is no
role exemption or password-only fallback. Google Authenticator and standard TOTP
apps work without a Google API connection or a Google account.

## Feature toggle

Set `MFA_ENABLED=False` in the deployment `.env` and restart the application to
temporarily disable MFA. Password authentication and role permissions continue
to apply. MFA setup links and screens remain hidden, while enrolled devices and
recovery codes stay intact. Set `MFA_ENABLED=True` and restart the application
to enforce MFA again. The secure production setting is `True`.

## User flow

1. Enter the existing SOC username and password.
2. On first use, select **Show my setup QR code**, scan it in the authenticator
   app, and confirm its six-digit code. Manual key entry is also available.
3. Save the ten recovery codes and acknowledge that they are stored safely.
4. Subsequent sign-ins require the password plus an app code or one unused
   recovery code. Password reset preserves the enrolled authenticator.

Setup and password-to-code verification expire after ten minutes. Normal
verified sessions retain the configured idle timeout (30 minutes by default)
and browser-close expiry. Existing password-only sessions must sign in again.
Navigation and queue counts are hidden until enrollment is complete.

The shield icon in the signed-in header opens recovery-code management.
Generating replacements requires the current password and a fresh app/recovery
code, invalidates all old recovery codes, and requires acknowledging the new
codes. Codes are displayed only during a ten-minute session, encrypted while
temporarily stored in the session, and removed after acknowledgment. Their
database records contain only SHA-256 digests of 128-bit random values.

## Deployment (Windows / Waitress)

Before releasing this change, arrange a pilot, make phones or compatible tokens
available, communicate that enrollment is mandatory, and confirm an IT recovery
contact. Prepare a protected server-console recovery route for administrators.

1. Install the updated `requirements.txt` in the deployment virtual environment.
2. Generate a new, dedicated key **on the deployment host**:

   ```powershell
   .\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   ```

3. Put that key in the deployment's protected `.env` as `MFA_ENCRYPTION_KEYS`.
   It must be separate from `SECRET_KEY`. Do not use the public CI/test key.
   Preserve it in the approved secret store, separately from database backups;
   losing it means enrolled authenticator secrets cannot be recovered. Include
   this additional secret in the protected standby/restore configuration.
4. Confirm HTTPS and the existing secure-cookie/proxy settings. Never transmit
   enrollment QR codes, passwords, or OTPs over a production HTTP connection.
5. Stop the application for the schema/code cutover, then run:

   ```powershell
   .\venv\Scripts\python.exe manage.py migrate --noinput
   .\venv\Scripts\python.exe manage.py check
   ```

6. Restart the existing Waitress service using the deployment runbook. Pilot
   enrollment with a normal user and a Django administrator before opening
   access to the full roster. Verify `/admin/`, attachments, reports, recovery,
   and an existing browser session. `/healthz` remains public for monitoring.

Do not migrate or test against a live database as part of development. The
automated suite uses Django's test database; the runtime MFA policy stays on.
Business-workflow test clients explicitly simulate a verified session. The MFA
test module uses the ordinary Django client to exercise the real flow.

## Lost phone / operator-assisted recovery

First use an unused recovery code with the account password. To replace the
authenticator, contact IT. In this release, device reset is an operator action
through a trusted server shell; there is no public email-only reset or disable
button. Verify the account owner's identity through the approved support
process before running the command. Being able to quote a username or receive
a password-reset email is not sufficient proof.

```powershell
.\venv\Scripts\python.exe manage.py reset_mfa USERNAME --actor ADMIN_USERNAME --reason "Support ticket reference and identity verification method"
```

`--actor` must identify an active Django superuser. This is audit attribution;
authorization to execute the command comes from controlled server-shell access.
Record the support reference without passwords, OTPs, or sensitive identity
documents. The command removes the old device and recovery codes, invalidates
verified sessions on their next request, records the operator/reason in MFA
audit history, and sends the account owner a notification. The user must enter
their password and complete setup again. It never grants a bypass session.

The console route also supports recovery of an administrator's own account
under the organization's server-access controls. If the identity cannot be
verified, do not reset the factor.

## Operations and security properties

- Keep server and phone time synchronized automatically. Codes use the standard
  30-second period with a one-step tolerance, and a used time step is rejected.
- Verification and recovery-code consumption use PostgreSQL row locks. Failed
  verification triggers account-wide exponential backoff, capped at 512 seconds;
  another login or pending-setup restart does not clear that throttle. Axes
  continues protecting password attempts.
- Audit history is read-only in Django admin. Enrollment, allowed failed
  attempts, verification, recovery use, code replacement, and resets are
  recorded without secret material. Account-security emails contain no secrets.
- Backup and restore the MFA tables with the rest of the application database.
  Treat restoration of an old database as a security event: it can revive
  previously consumed recovery codes and old session records. Invalidate restored
  sessions and reset/reissue affected credentials under the recovery procedure.
- `MFA_ENCRYPTION_KEYS` accepts a comma-separated list, newest first. New data
  uses the first key; old data can be decrypted with retained keys. Keep old
  keys until all encrypted device secrets and outstanding encrypted sessions
  have been re-encrypted or replaced. Removing a key prematurely locks users out.
- TOTP codes remain susceptible to phishing. Hardware-backed WebAuthn is a
  future enhancement for privileged accounts, not part of this release.

References: [django-otp extension API](https://django-otp-official.readthedocs.io/en/stable/extend.html),
[OWASP MFA guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html).
