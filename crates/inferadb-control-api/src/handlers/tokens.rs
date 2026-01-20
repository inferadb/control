use axum::{
    Extension, Form, Json,
    extract::{Path, State},
    http::StatusCode,
};
use inferadb_control_core::{
    IdGenerator, JwtSigner, MasterKey, PrivateKeyEncryptor, RepositoryContext, VaultTokenClaims,
    error::Error as CoreError,
};
use inferadb_control_types::{
    dto::{
        ClientAssertionRequest, ClientAssertionResponse, GenerateVaultTokenRequest,
        GenerateVaultTokenResponse, RefreshTokenRequest, RefreshTokenResponse,
        RevokeTokensResponse,
    },
    entities::{VaultRefreshToken, VaultRole},
};
use serde::Deserialize;

use crate::{
    handlers::auth::{AppState, Result},
    middleware::{OrganizationContext, SessionContext, get_user_vault_role},
};

// ============================================================================
// Token Generation Endpoint
// ============================================================================

/// Generate vault access token and refresh token
///
/// POST /v1/organizations/:org/vaults/:vault/tokens
/// Required: Session authentication + vault access
///
/// Generates a short-lived JWT access token (default 5 min) signed with a client certificate
/// and a refresh token (default 1 hour) for obtaining new access tokens.
pub async fn generate_vault_token(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Extension(session_ctx): Extension<SessionContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(req): Json<GenerateVaultTokenRequest>,
) -> Result<(StatusCode, Json<GenerateVaultTokenResponse>)> {
    // Verify vault exists and belongs to this organization
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get user's maximum vault role (their actual permission level)
    let max_vault_role = get_user_vault_role(&state, vault_id, org_ctx.member.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You do not have access to this vault".to_string()))?;

    // Determine the role to grant in the token
    let vault_role = if let Some(requested_role_str) = &req.requested_role {
        // Parse requested role
        let requested_role = match requested_role_str.as_str() {
            "read" => VaultRole::Reader,
            "write" => VaultRole::Writer,
            "admin" => VaultRole::Admin,
            _ => {
                return Err(CoreError::Validation(
                    "Invalid role. Must be one of: read, write, admin".to_string(),
                )
                .into());
            },
        };

        // Verify requested role doesn't exceed user's actual permission level
        if requested_role > max_vault_role {
            return Err(CoreError::Validation(format!(
                "Requested role '{}' exceeds your permission level '{}'",
                requested_role_str,
                match max_vault_role {
                    VaultRole::Reader => "read",
                    VaultRole::Writer => "write",
                    VaultRole::Admin => "admin",
                    VaultRole::Manager => "manage",
                }
            ))
            .into());
        }

        requested_role
    } else {
        // Default to Reader (principle of least privilege)
        VaultRole::Reader
    };

    // Get the client to use for signing

    // If client_id provided, use it; otherwise use the first active client
    let client = if let Some(client_id) = req.client_id {
        let c = repos
            .client
            .get(client_id)
            .await?
            .ok_or_else(|| CoreError::NotFound("Client not found".to_string()))?;

        // Verify client belongs to this organization
        if c.organization_id != org_ctx.organization_id {
            return Err(CoreError::NotFound("Client not found".to_string()).into());
        }

        c
    } else {
        // Get first active client for this organization
        let clients = repos.client.list_by_organization(org_ctx.organization_id).await?;

        clients.into_iter().find(|c| !c.is_deleted()).ok_or_else(|| {
            CoreError::NotFound(
                "No active clients found. Create a client first to generate tokens.".to_string(),
            )
        })?
    };

    // Get an active certificate for the client
    let certificates = repos.client_certificate.list_by_client(client.id).await?;
    let certificate =
        certificates.into_iter().find(|cert| !cert.is_revoked()).ok_or_else(|| {
            CoreError::NotFound(
                "No active certificates found for client. Create a certificate first.".to_string(),
            )
        })?;

    // Create JWT signer
    let master_key = MasterKey::load_or_generate(state.config.key_file.as_deref())?;
    let encryptor = PrivateKeyEncryptor::from_master_key(&master_key)?;
    let signer = JwtSigner::new(encryptor);

    // Create access token claims
    // Note: issuer and audience are hardcoded in VaultTokenClaims::new
    let access_ttl = req.access_token_ttl.unwrap_or(300); // Default 5 minutes (per spec)
    let claims =
        VaultTokenClaims::new(org_ctx.organization_id, client.id, vault_id, vault_role, access_ttl);

    // Sign the access token
    let access_token = signer.sign_vault_token(&claims, &certificate)?;

    // Generate refresh token
    let refresh_token_id = IdGenerator::next_id();
    let refresh_token = VaultRefreshToken::new_for_session(
        refresh_token_id,
        vault_id,
        org_ctx.organization_id,
        vault_role,
        session_ctx.session_id,
        req.refresh_token_ttl,
    )?;

    // Store refresh token
    repos.vault_refresh_token.create(refresh_token.clone()).await?;

    // Calculate refresh token TTL in seconds
    let refresh_ttl = (refresh_token.expires_at - refresh_token.created_at).num_seconds();

    Ok((
        StatusCode::CREATED,
        Json(GenerateVaultTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: access_ttl,
            refresh_expires_in: refresh_ttl,
            vault_id: vault_id.to_string(),
            vault_role: match vault_role {
                VaultRole::Reader => "read",
                VaultRole::Writer => "write",
                VaultRole::Admin => "admin",
                VaultRole::Manager => "manage",
            }
            .to_string(),
            refresh_token: refresh_token.token.clone(),
        }),
    ))
}

// ============================================================================
// Token Refresh Endpoint
// ============================================================================

/// Refresh vault access token using refresh token
///
/// POST /v1/tokens/refresh
/// No authentication required (refresh token provides authentication)
///
/// Validates the refresh token, generates a new access token, and rotates
/// the refresh token (one-time use for security).
pub async fn refresh_vault_token(
    State(state): State<AppState>,
    Json(req): Json<RefreshTokenRequest>,
) -> Result<(StatusCode, Json<RefreshTokenResponse>)> {
    let repos = RepositoryContext::new((*state.storage).clone());

    // Get refresh token by token string
    let mut old_token = repos
        .vault_refresh_token
        .get_by_token(&req.refresh_token)
        .await?
        .ok_or_else(|| CoreError::Authz("Invalid refresh token".to_string()))?;

    // Validate refresh token (checks expiration, used, revoked)
    old_token.validate_for_refresh()?;

    // Mark old token as used (prevents replay attacks)
    old_token.mark_used();
    repos.vault_refresh_token.update(&old_token).await?;

    // Validate the session is still active (for session-bound tokens)
    if let Some(session_id) = old_token.user_session_id {
        let session = repos
            .user_session
            .get(session_id)
            .await?
            .ok_or_else(|| CoreError::Authz("Session expired or revoked".to_string()))?;

        if session.is_expired() {
            return Err(CoreError::Authz("Session expired".to_string()).into());
        }
    }

    // Verify vault still exists
    repos
        .vault
        .get(old_token.vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault no longer exists".to_string()))?;

    // Get a client and certificate for signing

    // If token was bound to a client, use that client
    let client = if let Some(client_id) = old_token.org_api_key_id {
        let c = repos
            .client
            .get(client_id)
            .await?
            .ok_or_else(|| CoreError::Authz("Client no longer exists".to_string()))?;

        if c.is_deleted() {
            return Err(CoreError::Authz("Client has been deleted".to_string()).into());
        }

        c
    } else {
        // Get first active client for this organization
        let clients = repos.client.list_by_organization(old_token.organization_id).await?;

        clients
            .into_iter()
            .find(|c| !c.is_deleted())
            .ok_or_else(|| CoreError::Authz("No active clients available".to_string()))?
    };

    // Get an active certificate
    let certificates = repos.client_certificate.list_by_client(client.id).await?;
    let certificate = certificates
        .into_iter()
        .find(|cert| !cert.is_revoked())
        .ok_or_else(|| CoreError::Authz("No active certificates available".to_string()))?;

    // Create JWT signer
    let master_key = MasterKey::load_or_generate(state.config.key_file.as_deref())?;
    let encryptor = PrivateKeyEncryptor::from_master_key(&master_key)?;
    let signer = JwtSigner::new(encryptor);

    // Create new access token
    // Note: issuer and audience are hardcoded in VaultTokenClaims::new
    let access_ttl = req.access_token_ttl.unwrap_or(300); // Default 5 minutes (per spec)
    let claims = VaultTokenClaims::new(
        old_token.organization_id,
        client.id,
        old_token.vault_id,
        old_token.vault_role,
        access_ttl,
    );

    let access_token = signer.sign_vault_token(&claims, &certificate)?;

    // Generate new refresh token (rotation)
    let new_token_id = IdGenerator::next_id();
    let new_token = if let Some(session_id) = old_token.user_session_id {
        VaultRefreshToken::new_for_session(
            new_token_id,
            old_token.vault_id,
            old_token.organization_id,
            old_token.vault_role,
            session_id,
            None, // Use default TTL
        )?
    } else if let Some(client_id) = old_token.org_api_key_id {
        VaultRefreshToken::new_for_client(
            new_token_id,
            old_token.vault_id,
            old_token.organization_id,
            old_token.vault_role,
            client_id,
            None, // Use default TTL
        )?
    } else {
        return Err(CoreError::Internal("Invalid refresh token state".to_string()).into());
    };

    // Store new refresh token
    repos.vault_refresh_token.create(new_token.clone()).await?;

    // Calculate refresh token TTL in seconds
    let refresh_ttl = (new_token.expires_at - new_token.created_at).num_seconds();

    Ok((
        StatusCode::CREATED,
        Json(RefreshTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: access_ttl,
            refresh_expires_in: refresh_ttl,
            refresh_token: new_token.token.clone(),
        }),
    ))
}

// ============================================================================
// Request/Response Types - Client Assertion
// ============================================================================

/// Client assertion JWT claims (RFC 7523)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClientAssertionClaims {
    /// Issuer: client ID
    iss: String,
    /// Subject: client ID
    sub: String,
    /// Audience: token endpoint URL
    aud: String,
    /// Expiration time (Unix timestamp)
    exp: i64,
    /// Issued at (Unix timestamp)
    iat: i64,
    /// JWT ID (for replay protection)
    jti: String,
}

// ============================================================================
// Client Assertion Authentication Endpoint
// ============================================================================

/// Authenticate using OAuth 2.0 JWT Bearer client assertion (RFC 7523)
///
/// POST /v1/token
/// No authentication required (client assertion provides authentication)
///
/// This endpoint allows backend services to authenticate using a signed JWT
/// and obtain vault-scoped access tokens.
pub async fn client_assertion_authenticate(
    State(state): State<AppState>,
    Form(req): Form<ClientAssertionRequest>,
) -> Result<Json<ClientAssertionResponse>> {
    // Validate grant_type
    if req.grant_type != "client_credentials" {
        return Err(
            CoreError::Validation("grant_type must be 'client_credentials'".to_string()).into()
        );
    }

    // Validate client_assertion_type
    if req.client_assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
        return Err(CoreError::Validation(
            "client_assertion_type must be 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'"
                .to_string(),
        )
        .into());
    }

    // Parse vault_id
    let vault_id = req
        .vault_id
        .parse::<i64>()
        .map_err(|_| CoreError::Validation("invalid vault_id".to_string()))?;

    // Parse requested role (default to Reader for least privilege)
    let requested_role = if let Some(role_str) = &req.requested_role {
        match role_str.as_str() {
            "read" => VaultRole::Reader,
            "write" => VaultRole::Writer,
            "admin" => VaultRole::Admin,
            _ => {
                return Err(CoreError::Validation(
                    "invalid role (must be read, write, or admin)".to_string(),
                )
                .into());
            },
        }
    } else {
        VaultRole::Reader // Default to read per spec
    };

    // Decode JWT header to extract kid (key ID)
    use jsonwebtoken::decode_header;
    let header = decode_header(&req.client_assertion)
        .map_err(|e| CoreError::Auth(format!("Invalid client assertion JWT: {e}")))?;

    let kid = header.kid.ok_or_else(|| {
        CoreError::Auth("client assertion JWT missing 'kid' in header".to_string())
    })?;

    // Lookup certificate by kid
    // kid format: "org-<org_id>-client-<client_id>-cert-<cert_id>"
    let repos = RepositoryContext::new((*state.storage).clone());

    // Parse kid to extract cert_id
    let kid_parts: Vec<&str> = kid.split('-').collect();
    if kid_parts.len() != 8
        || kid_parts[0] != "org"
        || kid_parts[2] != "client"
        || kid_parts[4] != "cert"
    {
        return Err(CoreError::Auth(format!("Invalid kid format: {kid}")).into());
    }

    let _org_id = kid_parts[1]
        .parse::<i64>()
        .map_err(|_| CoreError::Auth("Invalid org_id in kid".to_string()))?;
    let _client_id = kid_parts[3]
        .parse::<i64>()
        .map_err(|_| CoreError::Auth("Invalid client_id in kid".to_string()))?;
    let cert_id = kid_parts[5]
        .parse::<i64>()
        .map_err(|_| CoreError::Auth("Invalid cert_id in kid".to_string()))?;

    // Get the certificate
    let certificate = repos
        .client_certificate
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::Auth(format!("No certificate found with kid: {kid}")))?;

    // Verify kid matches
    if certificate.kid != kid {
        return Err(CoreError::Auth("Certificate kid mismatch".to_string()).into());
    }

    if certificate.is_revoked() {
        return Err(CoreError::Auth("Certificate has been revoked".to_string()).into());
    }

    // Verify JWT signature using certificate public key
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    let public_key_bytes = BASE64
        .decode(&certificate.public_key)
        .map_err(|e| CoreError::Internal(format!("Failed to decode public key: {e}")))?;

    if public_key_bytes.len() != 32 {
        return Err(CoreError::Internal("Invalid public key length".to_string()).into());
    }

    // Convert public key to PEM (same as in jwt.rs)
    let mut spki_der = vec![
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (algorithm)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112
        0x03, 0x21, 0x00, // BIT STRING (33 bytes, 0 unused bits)
    ];
    spki_der.extend_from_slice(&public_key_bytes);

    let public_key_pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        BASE64.encode(&spki_der)
    );

    let decoding_key = DecodingKey::from_ed_pem(public_key_pem.as_bytes())
        .map_err(|e| CoreError::Internal(format!("Failed to create decoding key: {e}")))?;

    // Set up validation - expect token endpoint as audience
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["https://api.inferadb.com/token"]);

    // Decode and verify JWT
    let token_data =
        decode::<ClientAssertionClaims>(&req.client_assertion, &decoding_key, &validation)
            .map_err(|e| CoreError::Auth(format!("Failed to verify client assertion: {e}")))?;

    let claims = token_data.claims;

    // Validate claims
    // iss and sub must match client_id (certificate owner)
    let expected_client_id = certificate.client_id.to_string();
    if claims.iss != expected_client_id || claims.sub != expected_client_id {
        return Err(
            CoreError::Auth("client assertion iss/sub must match client_id".to_string()).into()
        );
    }

    // Check JTI for replay protection
    let expires_at =
        chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(chrono::Utc::now);

    repos.jti_replay_protection.check_and_mark_jti(&claims.jti, expires_at).await?;

    // Get client and verify it's not deleted
    let client = repos
        .client
        .get(certificate.client_id)
        .await?
        .ok_or_else(|| CoreError::Auth("Client not found".to_string()))?;

    if client.is_deleted() {
        return Err(CoreError::Auth("Client has been deleted".to_string()).into());
    }

    // Verify vault exists
    let repos = RepositoryContext::new((*state.storage).clone());
    let vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    // Verify client has permission for requested role on this vault
    // Note: This is a simplified check. In production, you'd verify client has appropriate grants.
    // For now, we just verify the vault belongs to the same organization as the client.
    if vault.organization_id != client.organization_id {
        return Err(
            CoreError::Authz("Client does not have access to this vault".to_string()).into()
        );
    }

    // Create JWT signer
    let master_key = MasterKey::load_or_generate(state.config.key_file.as_deref())?;
    let encryptor = PrivateKeyEncryptor::from_master_key(&master_key)?;
    let signer = JwtSigner::new(encryptor);

    // Generate vault-scoped JWT (5 minutes default per spec)
    // Note: issuer and audience are hardcoded in VaultTokenClaims::new
    let access_ttl = 300;
    let vault_claims = VaultTokenClaims::new(
        client.organization_id,
        client.id,
        vault_id,
        requested_role,
        access_ttl,
    );

    let access_token = signer.sign_vault_token(&vault_claims, &certificate)?;

    // Generate refresh token (7 days for clients)
    let refresh_token_id = IdGenerator::next_id();
    let refresh_token = VaultRefreshToken::new_for_client(
        refresh_token_id,
        vault_id,
        client.organization_id,
        requested_role,
        client.id,
        None, // Use default TTL (7 days)
    )?;

    repos.vault_refresh_token.create(refresh_token.clone()).await?;

    // Build scope string based on role
    let scope = match requested_role {
        VaultRole::Reader => "vault:read",
        VaultRole::Writer => "vault:read vault:write",
        VaultRole::Manager => "vault:read vault:write vault:manage",
        VaultRole::Admin => "vault:read vault:write vault:manage vault:admin",
    }
    .to_string();

    let vault_role_str = match requested_role {
        VaultRole::Reader => "read",
        VaultRole::Writer => "write",
        VaultRole::Manager => "manage",
        VaultRole::Admin => "admin",
    };

    Ok(Json(ClientAssertionResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl,
        scope,
        vault_role: vault_role_str.to_string(),
        refresh_token: refresh_token.token,
    }))
}

// ============================================================================
// Token Revocation Endpoint
// ============================================================================

/// Revoke all refresh tokens for a vault
///
/// POST /v1/tokens/revoke/vault/:vault_id
/// Requires session authentication
///
/// This revokes all active refresh tokens for the specified vault.
/// Useful when vault access changes or vault is being deleted.
pub async fn revoke_vault_tokens(
    State(state): State<AppState>,
    Extension(session_ctx): Extension<SessionContext>,
    Path(vault_id): Path<i64>,
) -> Result<(StatusCode, Json<RevokeTokensResponse>)> {
    // Verify user has session
    let repos = RepositoryContext::new((*state.storage).clone());
    let session = repos
        .user_session
        .get(session_ctx.session_id)
        .await?
        .ok_or_else(|| CoreError::Auth("Session not found".to_string()))?;

    if session.is_expired() {
        return Err(CoreError::Auth("Session expired".to_string()).into());
    }

    // Verify vault exists
    let _vault = repos
        .vault
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    // Verify user has access to this vault (must be admin or have vault access)
    let user_id = session.user_id;
    let vault_role = get_user_vault_role(&state, vault_id, user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You do not have access to this vault".to_string()))?;

    // Only admins can revoke tokens
    if vault_role != VaultRole::Admin {
        return Err(CoreError::Authz("Only vault admins can revoke tokens".to_string()).into());
    }

    // Revoke all refresh tokens for this vault
    let revoked_count = repos.vault_refresh_token.revoke_by_vault(vault_id).await?;

    Ok((StatusCode::CREATED, Json(RevokeTokensResponse { revoked_count })))
}
