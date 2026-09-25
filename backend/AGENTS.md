# Contents

- `backend/` defines the backend factories a product instantiates with its
  own wire namespace and bounds through `defineRelay` in `index.ts`.

# Guidelines

- Use one verified-email credentials provider. Do not add a second
  identity provider or accept email as authority after login.
- Store only purpose-separated challenge digests. Codes are one-time,
  rate-limited, and expire.
- Treat authenticated user + active device + current auth epoch as the
  minimum write authority; daemon-addressed commands additionally require
  the target's current boot authority generation.
- Never accept plaintext session content, provider credentials, raw
  protocol data, raw reasoning, approval secrets, arbitrary tool output,
  or environment values.
- Close an effect that may already have begun as `ambiguous` under a
  strictly later authority. Never let recovery publish `applied` for an
  effect it did not observe.
- Add a table only with an explicit entry in every exhaustive hosted map:
  lifecycle policy, quota genesis, account deletion, device revocation,
  and the maintenance categories that sweep it.
