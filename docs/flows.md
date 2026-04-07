# Data flows

Sequence diagrams for each authentication and token operation in InferaDB Control.

## Why it matters

These diagrams show the exact request/response sequences between your client, Control, Ledger, and the Email service. Use them to implement client integrations correctly and to debug authentication issues.

## Quickstart

The most common flow is email code login for an existing user:

```bash
# Step 1: Get a verification code
curl -X POST /control/v1/auth/email/initiate \
  -d '{"email": "you@example.com"}'

# Step 2: Verify the code
curl -X POST /control/v1/auth/email/verify \
  -d '{"email": "you@example.com", "code": "ABC123"}'
# -> {"status": "authenticated", "access_token": "...", "refresh_token": "..."}
```

## Registration (new user)

A new user goes through all three email auth steps: initiate, verify, and complete.

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger
    participant Email as Email Service

    Client->>Control: POST /control/v1/auth/email/initiate<br/>{"email": "new@example.com", "region": "us-east-va"}
    Control->>Control: Validate email format
    Control->>Ledger: initiate_email_verification(email, region)
    Ledger-->>Control: {code: "ABC123"}
    Control->>Email: Send verification email (code, 10 min expiry)
    Control-->>Client: 200 {"message": "verification code sent"}

    Client->>Control: POST /control/v1/auth/email/verify<br/>{"email": "new@example.com", "code": "ABC123"}
    Control->>Ledger: verify_email_code(email, code, region)
    Ledger-->>Control: NewUser {onboarding_token}
    Control-->>Client: 200 {"status": "registration_required",<br/>"onboarding_token": "obt_..."}

    Note over Client: Rate limit: 5/day per IP

    Client->>Control: POST /control/v1/auth/email/complete<br/>{"onboarding_token": "obt_...",<br/>"email": "new@example.com",<br/>"name": "Alice",<br/>"organization_name": "Acme Corp"}
    Control->>Control: Validate email, name, org name
    Control->>Ledger: complete_registration(token, email, region, name, org_name)
    Ledger-->>Control: {user, organization, session: {access_token, refresh_token}}
    Control-->>Client: 200 {"registration": {"user": 123,<br/>"organization": 456,<br/>"access_token": "eyJ...",<br/>"refresh_token": "opaque-token",<br/>"token_type": "Bearer"}}

    Note over Client: Cookies set:<br/>inferadb_access (path=/, 15 min)<br/>inferadb_refresh (path=/control/v1/auth, 30 days)
```

## Login (existing user, no TOTP)

An existing user without TOTP completes authentication in two steps.

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger
    participant Email as Email Service

    Client->>Control: POST /control/v1/auth/email/initiate<br/>{"email": "alice@example.com"}
    Control->>Ledger: initiate_email_verification(email, region)
    Ledger-->>Control: {code}
    Control->>Email: Send verification email
    Control-->>Client: 200 {"message": "verification code sent"}

    Client->>Control: POST /control/v1/auth/email/verify<br/>{"email": "alice@example.com", "code": "XYZ789"}
    Control->>Ledger: verify_email_code(email, code, region)
    Ledger-->>Control: ExistingUser {session: {access_token, refresh_token}}
    Control-->>Client: 200 {"status": "authenticated",<br/>"access_token": "eyJ...",<br/>"refresh_token": "opaque-token",<br/>"token_type": "Bearer"}

    Note over Client: Cookies set:<br/>inferadb_access (15 min)<br/>inferadb_refresh (30 days)
```

## Login with TOTP

When TOTP is enabled, the verify step returns a challenge nonce instead of tokens. The client must complete a second factor.

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger

    Note over Client,Ledger: Steps 1-2: same as standard login

    Client->>Control: POST /control/v1/auth/email/verify<br/>{"email": "alice@example.com", "code": "XYZ789"}
    Control->>Ledger: verify_email_code(email, code, region)
    Ledger-->>Control: TotpRequired {challenge_nonce}
    Control-->>Client: 200 {"status": "totp_required",<br/>"challenge_nonce": "<base64>"}

    alt TOTP code
        Client->>Control: POST /control/v1/auth/totp/verify<br/>{"user_slug": 123,<br/>"totp_code": "654321",<br/>"challenge_nonce": "<base64>"}
        Control->>Ledger: verify_totp(user, totp_code, nonce)
        Ledger-->>Control: {access_token, refresh_token}
        Control-->>Client: 200 {"access_token": "eyJ...",<br/>"refresh_token": "opaque-token",<br/>"token_type": "Bearer"}
    else Recovery code
        Client->>Control: POST /control/v1/auth/recovery<br/>{"user_slug": 123,<br/>"code": "ABCD1234",<br/>"challenge_nonce": "<base64>"}
        Control->>Ledger: consume_recovery_code(user, code, nonce)
        Ledger-->>Control: {tokens, remaining_codes}
        Control-->>Client: 200 {"access_token": "eyJ...",<br/>"refresh_token": "opaque-token",<br/>"token_type": "Bearer",<br/>"remaining_codes": 9}
    end

    Note over Client: Cookies set on success
```

## Passkey authentication

Passkey authentication uses a two-step WebAuthn ceremony. Challenge state is encrypted into the `challenge_id` (no server-side storage).

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger

    Client->>Control: POST /control/v1/auth/passkey/begin<br/>{"user_slug": 123}
    Control->>Ledger: list_user_credentials(user, Passkey)
    Ledger-->>Control: [passkey credentials]
    Control->>Control: Generate WebAuthn challenge<br/>Encrypt state into challenge_id (AES-256-GCM, 60s TTL)
    Control-->>Client: 200 {"challenge_id": "<encrypted>",<br/>"challenge": {/* RequestChallengeResponse */}}

    Note over Client: Browser executes<br/>navigator.credentials.get()

    Client->>Control: POST /control/v1/auth/passkey/finish<br/>{"challenge_id": "<encrypted>",<br/>"credential": {/* PublicKeyCredential */}}
    Control->>Control: Decrypt and validate challenge state
    Control->>Control: Verify WebAuthn response
    Control->>Ledger: list_user_credentials(user, Passkey) + list_user_credentials(user, Totp)
    Control->>Ledger: update_user_credential (sign count)

    alt No TOTP
        Control->>Ledger: create_user_session(user)
        Ledger-->>Control: {access_token, refresh_token}
        Control-->>Client: 200 {"status": "authenticated",<br/>"access_token": "eyJ...",<br/>"refresh_token": "opaque-token",<br/>"token_type": "Bearer"}
    else TOTP enabled
        Control->>Ledger: create_totp_challenge(user, "passkey")
        Ledger-->>Control: challenge_nonce
        Control-->>Client: 200 {"status": "totp_required",<br/>"challenge_nonce": "<base64>"}
        Note over Client: Complete TOTP flow (see above)
    end
```

## Passkey registration

Requires an existing authenticated session. The registration endpoints are write routes (Ledger-validated JWT).

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger

    Client->>Control: POST /control/v1/users/me/credentials/passkeys/begin<br/>Authorization: Bearer {access_token}<br/>{"name": "My MacBook"}
    Control->>Control: Validate JWT (Ledger round-trip)
    Control->>Ledger: list_user_credentials(user, Passkey)
    Ledger-->>Control: [existing passkeys] (exclude list)
    Control->>Control: Generate WebAuthn registration challenge
    Control-->>Client: 200 {"challenge_id": "<encrypted>",<br/>"challenge": {/* CreationChallengeResponse */}}

    Note over Client: Browser executes<br/>navigator.credentials.create()

    Client->>Control: POST /control/v1/users/me/credentials/passkeys/finish<br/>Authorization: Bearer {access_token}<br/>{"challenge_id": "<encrypted>",<br/>"name": "My MacBook",<br/>"credential": {/* RegisterPublicKeyCredential */}}
    Control->>Control: Validate JWT, decrypt challenge, verify WebAuthn response
    Control->>Ledger: create_user_credential(user, name, credential_data)
    Ledger-->>Control: {id, name}
    Control-->>Client: 200 {"slug": 789, "name": "My MacBook"}
```

## Vault token generation

Authenticated users generate vault tokens to access the Engine.

```mermaid
sequenceDiagram
    participant App as Application
    participant Control
    participant Ledger
    participant Engine

    App->>Control: POST /control/v1/organizations/{org}/vaults/{vault}/tokens<br/>Authorization: Bearer {access_token}<br/>{"app": 42, "scopes": ["vault:read", "vault:write"]}
    Control->>Ledger: validate_token (JWT write-route validation)
    Control->>Ledger: get_app(org, user, app)
    Ledger-->>Control: App details (verifies caller access)
    Control->>Ledger: create_vault_token(org, app, vault, scopes)
    Ledger-->>Control: {access_token, refresh_token, expires_at}
    Control-->>App: 201 {"access_token": "<vault-jwt>",<br/>"refresh_token": "<opaque>",<br/>"token_type": "Bearer",<br/>"expires_in": 300}

    App->>Engine: POST /check<br/>Authorization: Bearer {vault-jwt}
    Engine->>Engine: Validate JWT (JWKS, Ed25519)
    Engine-->>App: Authorization decision
```

## Client assertion (machine-to-machine)

Backend services authenticate via OAuth 2.0 JWT Bearer (RFC 7523). The client signs a JWT with its Ed25519 private key.

```mermaid
sequenceDiagram
    participant Backend
    participant Control
    participant Ledger

    Note over Backend: Create JWT assertion:<br/>{iss: client_id, sub: client_id,<br/>aud: token_endpoint,<br/>exp: now+60s, iat: now, jti: uuid}<br/>Sign with Ed25519 private key

    Backend->>Control: POST /control/v1/token<br/>{"grant_type": "client_credentials",<br/>"client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",<br/>"client_assertion": "<signed-jwt>",<br/>"organization": 123,<br/>"vault": "456",<br/>"scopes": ["vault:read"]}
    Control->>Control: Validate grant_type and assertion_type
    Control->>Ledger: authenticate_client_assertion(org, vault, assertion, scopes)
    Note over Ledger: Parse assertion JWT<br/>Look up client by iss/sub<br/>Verify Ed25519 signature<br/>Validate claims (aud, exp, jti)
    Ledger-->>Control: {access_token, refresh_token, expires_at}
    Control-->>Backend: 201 {"access_token": "<vault-jwt>",<br/>"refresh_token": "<opaque>",<br/>"token_type": "Bearer",<br/>"expires_in": 300}
```

## Session refresh

### User session refresh

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger

    Client->>Control: POST /control/v1/auth/refresh<br/>{"refresh_token": "<opaque>"}<br/>or Cookie: inferadb_refresh=<opaque>
    Control->>Ledger: refresh_token(token)
    Note over Ledger: Validate token<br/>Mark as used (single-use)<br/>Issue new pair
    Ledger-->>Control: {access_token, refresh_token}
    Control-->>Client: 200 {"access_token": "eyJ...",<br/>"refresh_token": "<new-opaque>",<br/>"token_type": "Bearer"}

    Note over Client: Old refresh token is invalidated.<br/>Cookies updated with new pair.
```

### Vault token refresh

```mermaid
sequenceDiagram
    participant App
    participant Control
    participant Ledger

    App->>Control: POST /control/v1/tokens/refresh<br/>{"refresh_token": "<opaque>"}
    Control->>Ledger: refresh_token(token)
    Ledger-->>Control: {access_token, refresh_token, expires_at}
    Control-->>App: 200 {"access_token": "<vault-jwt>",<br/>"refresh_token": "<new-opaque>",<br/>"token_type": "Bearer",<br/>"expires_in": 300}
```

## Logout and revocation

### Logout (current session)

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger

    Client->>Control: POST /control/v1/auth/logout<br/>Cookie: inferadb_refresh=<opaque>
    Control->>Ledger: revoke_token(refresh_token)
    Note over Ledger: Best-effort revocation
    Control-->>Client: 200 {"message": "logged out"}<br/>Set-Cookie: inferadb_access=; Max-Age=0<br/>Set-Cookie: inferadb_refresh=; Max-Age=0
```

### Revoke all sessions

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger

    Client->>Control: POST /control/v1/auth/revoke-all<br/>Authorization: Bearer {access_token}
    Control->>Ledger: validate_token (write-route JWT validation)
    Control->>Ledger: revoke_all_user_sessions(user_slug)
    Ledger-->>Control: {revoked_count}
    Control-->>Client: 200 {"revoked_count": 5}<br/>Cookies cleared
```

### Revoke vault tokens

```mermaid
sequenceDiagram
    participant Admin
    participant Control
    participant Ledger

    Admin->>Control: DELETE /control/v1/organizations/{org}/vaults/{vault}/tokens<br/>Authorization: Bearer {access_token}<br/>{"app": 42}
    Control->>Ledger: get_app(org, user, app) — verify access
    Control->>Ledger: revoke_all_app_sessions(app)
    Ledger-->>Control: {revoked_count}
    Control-->>Admin: 200 {"revoked_count": 3}
```

## Email verification

Verify an additional email address added to a user account.

```mermaid
sequenceDiagram
    participant User
    participant Control
    participant Ledger

    User->>Control: POST /control/v1/auth/verify-email<br/>{"token": "<verification-token>"}
    Control->>Ledger: verify_user_email(token)
    Ledger-->>Control: Email verified
    Control-->>User: 200 {"message": "Email verified successfully",<br/>"verified": true}
```

## Rate limiting

All login-related endpoints share a rate limit bucket. Registration has a stricter limit.

```mermaid
sequenceDiagram
    participant Client
    participant Control
    participant Ledger as Rate Limiter (Ledger-backed)

    Client->>Control: POST /control/v1/auth/email/initiate
    Control->>Ledger: check(login_ip, client_ip, 100/hour)
    Ledger-->>Control: Allowed (count: 1/100)
    Control->>Control: Process request
    Control-->>Client: 200 OK

    Note over Client: After 100 requests in 1 hour...

    Client->>Control: POST /control/v1/auth/email/initiate
    Control->>Ledger: check(login_ip, client_ip, 100/hour)
    Ledger-->>Control: Limited {retry_after_secs}
    Control-->>Client: 429 Too Many Requests<br/>Retry-After: {seconds}
```

**Rate limit buckets:**

| Bucket            | Endpoints                                                                                                                                                                           | Limit           |
| ----------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| `login_ip`        | `/auth/email/initiate`, `/auth/email/verify`, `/auth/totp/verify`, `/auth/recovery`, `/auth/passkey/begin`, `/auth/passkey/finish`, `/token`, `/auth/refresh`, `/auth/verify-email` | 100/hour per IP |
| `registration_ip` | `/auth/email/complete`                                                                                                                                                              | 5/day per IP    |

## Further reading

- [Authentication](authentication.md): Token types, security properties, and configuration reference
- [Architecture](architecture.md): System architecture and deployment topology
