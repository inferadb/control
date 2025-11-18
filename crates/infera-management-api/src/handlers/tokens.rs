use crate::handlers::auth::{AppState, Result};
use crate::middleware::{get_user_vault_role, OrganizationContext, SessionContext};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Extension, Form, Json,
};
use infera_management_core::{
    error::Error as CoreError, ClientCertificateRepository, ClientRepository, IdGenerator,
    JtiReplayProtectionRepository, JwtSigner, PrivateKeyEncryptor, UserSessionRepository,
    VaultRefreshToken, VaultRefreshTokenRepository, VaultRepository, VaultRole, VaultTokenClaims,
};
use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types - Token Generation
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct GenerateVaultTokenRequest {
    /// Client ID to use for signing (optional, defaults to first active client cert)
    pub client_id: Option<i64>,
    /// TTL for access token in seconds (default: 3600 = 1 hour)
    pub access_token_ttl: Option<i64>,
    /// TTL for refresh token in seconds (default: 86400 = 24 hours for sessions)
    pub refresh_token_ttl: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct GenerateVaultTokenResponse {
    /// Short-lived JWT access token
    pub access_token: String,
    /// Type of token (always "Bearer")
    pub token_type: String,
    /// Access token expiration time (Unix timestamp)
    pub expires_at: i64,
    /// Long-lived refresh token (hex-encoded)
    pub refresh_token: String,
    /// Refresh token expiration time (Unix timestamp)
    pub refresh_token_expires_at: i64,
}

// ============================================================================
// Request/Response Types - Token Refresh
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    /// Refresh token (hex-encoded)
    pub refresh_token: String,
    /// TTL for new access token in seconds (default: 3600 = 1 hour)
    pub access_token_ttl: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    /// New short-lived JWT access token
    pub access_token: String,
    /// Type of token (always "Bearer")
    pub token_type: String,
    /// Access token expiration time (Unix timestamp)
    pub expires_at: i64,
    /// New refresh token (rotation)
    pub refresh_token: String,
    /// New refresh token expiration time (Unix timestamp)
    pub refresh_token_expires_at: i64,
}

// ============================================================================
// Token Generation Endpoint
// ============================================================================

/// Generate vault access token and refresh token
///
/// POST /v1/organizations/:org/vaults/:vault/tokens
/// Required: Session authentication + vault access
///
/// Generates a short-lived JWT access token signed with a client certificate
/// and a long-lived refresh token for obtaining new access tokens.
pub async fn generate_vault_token(
    State(state): State<AppState>,
    Extension(org_ctx): Extension<OrganizationContext>,
    Extension(session_ctx): Extension<SessionContext>,
    Path((_org_id, vault_id)): Path<(i64, i64)>,
    Json(req): Json<GenerateVaultTokenRequest>,
) -> Result<(StatusCode, Json<GenerateVaultTokenResponse>)> {
    // Verify vault exists and belongs to this organization
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault = vault_repo
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    if vault.organization_id != org_ctx.organization_id {
        return Err(CoreError::NotFound("Vault not found".to_string()).into());
    }

    // Get user's vault role
    let vault_role = get_user_vault_role(&state, vault_id, org_ctx.member.user_id)
        .await?
        .ok_or_else(|| CoreError::Authz("You do not have access to this vault".to_string()))?;

    // Get the client to use for signing
    let client_repo = ClientRepository::new((*state.storage).clone());
    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());

    // If client_id provided, use it; otherwise use the first active client
    let client = if let Some(client_id) = req.client_id {
        let c = client_repo
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
        let clients = client_repo
            .list_by_organization(org_ctx.organization_id)
            .await?;

        clients
            .into_iter()
            .find(|c| !c.is_deleted())
            .ok_or_else(|| {
                CoreError::NotFound(
                    "No active clients found. Create a client first to generate tokens."
                        .to_string(),
                )
            })?
    };

    // Get an active certificate for the client
    let certificates = cert_repo.list_by_client(client.id).await?;
    let certificate = certificates
        .into_iter()
        .find(|cert| !cert.is_revoked())
        .ok_or_else(|| {
            CoreError::NotFound(
                "No active certificates found for client. Create a certificate first.".to_string(),
            )
        })?;

    // Create JWT signer
    let key_secret = state
        .config
        .auth
        .key_encryption_secret
        .as_ref()
        .ok_or_else(|| CoreError::Config("key_encryption_secret not configured".to_string()))?;
    let encryptor = PrivateKeyEncryptor::new(key_secret.as_bytes())?;
    let signer = JwtSigner::new(encryptor);

    // Create access token claims
    let access_ttl = req.access_token_ttl.unwrap_or(3600); // Default 1 hour
    let claims = VaultTokenClaims::new(org_ctx.organization_id, vault_id, vault_role, access_ttl);

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
    let refresh_repo = VaultRefreshTokenRepository::new((*state.storage).clone());
    refresh_repo.create(refresh_token.clone()).await?;

    Ok((
        StatusCode::CREATED,
        Json(GenerateVaultTokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_at: claims.exp,
            refresh_token: refresh_token.token.clone(),
            refresh_token_expires_at: refresh_token.expires_at.timestamp(),
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
) -> Result<Json<RefreshTokenResponse>> {
    let refresh_repo = VaultRefreshTokenRepository::new((*state.storage).clone());

    // Get refresh token by token string
    let mut old_token = refresh_repo
        .get_by_token(&req.refresh_token)
        .await?
        .ok_or_else(|| CoreError::Authz("Invalid refresh token".to_string()))?;

    // Validate refresh token (checks expiration, used, revoked)
    old_token.validate_for_refresh()?;

    // Mark old token as used (prevents replay attacks)
    old_token.mark_used();
    refresh_repo.update(&old_token).await?;

    // Validate the session is still active (for session-bound tokens)
    if let Some(session_id) = old_token.user_session_id {
        let session_repo = UserSessionRepository::new((*state.storage).clone());
        let session = session_repo
            .get(session_id)
            .await?
            .ok_or_else(|| CoreError::Authz("Session expired or revoked".to_string()))?;

        if session.is_expired() {
            return Err(CoreError::Authz("Session expired".to_string()).into());
        }
    }

    // Verify vault still exists
    let vault_repo = VaultRepository::new((*state.storage).clone());
    vault_repo
        .get(old_token.vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault no longer exists".to_string()))?;

    // Get a client and certificate for signing
    let client_repo = ClientRepository::new((*state.storage).clone());
    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());

    // If token was bound to a client, use that client
    let client = if let Some(client_id) = old_token.org_api_key_id {
        let c = client_repo
            .get(client_id)
            .await?
            .ok_or_else(|| CoreError::Authz("Client no longer exists".to_string()))?;

        if c.is_deleted() {
            return Err(CoreError::Authz("Client has been deleted".to_string()).into());
        }

        c
    } else {
        // Get first active client for this organization
        let clients = client_repo
            .list_by_organization(old_token.organization_id)
            .await?;

        clients
            .into_iter()
            .find(|c| !c.is_deleted())
            .ok_or_else(|| CoreError::Authz("No active clients available".to_string()))?
    };

    // Get an active certificate
    let certificates = cert_repo.list_by_client(client.id).await?;
    let certificate = certificates
        .into_iter()
        .find(|cert| !cert.is_revoked())
        .ok_or_else(|| CoreError::Authz("No active certificates available".to_string()))?;

    // Create JWT signer
    let key_secret = state
        .config
        .auth
        .key_encryption_secret
        .as_ref()
        .ok_or_else(|| CoreError::Config("key_encryption_secret not configured".to_string()))?;
    let encryptor = PrivateKeyEncryptor::new(key_secret.as_bytes())?;
    let signer = JwtSigner::new(encryptor);

    // Create new access token
    let access_ttl = req.access_token_ttl.unwrap_or(3600); // Default 1 hour
    let claims = VaultTokenClaims::new(
        old_token.organization_id,
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
    refresh_repo.create(new_token.clone()).await?;

    Ok(Json(RefreshTokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_at: claims.exp,
        refresh_token: new_token.token.clone(),
        refresh_token_expires_at: new_token.expires_at.timestamp(),
    }))
}

// ============================================================================
// Request/Response Types - Client Assertion
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ClientAssertionRequest {
    /// Must be "client_credentials"
    pub grant_type: String,
    /// Must be "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    pub client_assertion_type: String,
    /// Signed JWT containing client assertion
    pub client_assertion: String,
    /// Scope in format: `vault:<vault_id>:<role>`
    pub scope: String,
}

#[derive(Debug, Serialize)]
pub struct ClientAssertionResponse {
    /// Short-lived JWT access token
    pub access_token: String,
    /// Type of token (always "Bearer")
    pub token_type: String,
    /// Access token expiration time in seconds
    pub expires_in: i64,
    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
}

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
            CoreError::Validation("grant_type must be 'client_credentials'".to_string()).into(),
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

    // Parse scope: "vault:<vault_id>:<role>"
    let scope_parts: Vec<&str> = req.scope.split(':').collect();
    if scope_parts.len() != 3 || scope_parts[0] != "vault" {
        return Err(CoreError::Validation(
            "scope must be in format 'vault:<vault_id>:<role>'".to_string(),
        )
        .into());
    }

    let vault_id = scope_parts[1]
        .parse::<i64>()
        .map_err(|_| CoreError::Validation("invalid vault_id in scope".to_string()))?;

    let requested_role = match scope_parts[2] {
        "read" => VaultRole::Reader,
        "write" => VaultRole::Writer,
        "manage" => VaultRole::Manager,
        "admin" => VaultRole::Admin,
        _ => {
            return Err(CoreError::Validation(
                "invalid role in scope (must be read, write, manage, or admin)".to_string(),
            )
            .into())
        }
    };

    // Decode JWT header to extract kid (key ID)
    use jsonwebtoken::decode_header;
    let header = decode_header(&req.client_assertion)
        .map_err(|e| CoreError::Auth(format!("Invalid client assertion JWT: {}", e)))?;

    let kid = header.kid.ok_or_else(|| {
        CoreError::Auth("client assertion JWT missing 'kid' in header".to_string())
    })?;

    // Lookup certificate by kid
    // kid format: "org-<org_id>-client-<client_id>-cert-<cert_id>"
    let cert_repo = ClientCertificateRepository::new((*state.storage).clone());
    let client_repo = ClientRepository::new((*state.storage).clone());

    // Parse kid to extract cert_id
    let kid_parts: Vec<&str> = kid.split('-').collect();
    if kid_parts.len() != 8
        || kid_parts[0] != "org"
        || kid_parts[2] != "client"
        || kid_parts[4] != "cert"
    {
        return Err(CoreError::Auth(format!("Invalid kid format: {}", kid)).into());
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
    let certificate = cert_repo
        .get(cert_id)
        .await?
        .ok_or_else(|| CoreError::Auth(format!("No certificate found with kid: {}", kid)))?;

    // Verify kid matches
    if certificate.kid != kid {
        return Err(CoreError::Auth("Certificate kid mismatch".to_string()).into());
    }

    if certificate.is_revoked() {
        return Err(CoreError::Auth("Certificate has been revoked".to_string()).into());
    }

    // Verify JWT signature using certificate public key
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    let public_key_bytes = BASE64
        .decode(&certificate.public_key)
        .map_err(|e| CoreError::Internal(format!("Failed to decode public key: {}", e)))?;

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
        .map_err(|e| CoreError::Internal(format!("Failed to create decoding key: {}", e)))?;

    // Set up validation - expect token endpoint as audience
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_audience(&["https://api.inferadb.com/token"]);

    // Decode and verify JWT
    let token_data =
        decode::<ClientAssertionClaims>(&req.client_assertion, &decoding_key, &validation)
            .map_err(|e| CoreError::Auth(format!("Failed to verify client assertion: {}", e)))?;

    let claims = token_data.claims;

    // Validate claims
    // iss and sub must match client_id (certificate owner)
    let expected_client_id = certificate.client_id.to_string();
    if claims.iss != expected_client_id || claims.sub != expected_client_id {
        return Err(
            CoreError::Auth("client assertion iss/sub must match client_id".to_string()).into(),
        );
    }

    // Check JTI for replay protection
    let jti_repo = JtiReplayProtectionRepository::new((*state.storage).clone());
    let expires_at =
        chrono::DateTime::from_timestamp(claims.exp, 0).unwrap_or_else(chrono::Utc::now);

    jti_repo.check_and_mark_jti(&claims.jti, expires_at).await?;

    // Get client and verify it's not deleted
    let client = client_repo
        .get(certificate.client_id)
        .await?
        .ok_or_else(|| CoreError::Auth("Client not found".to_string()))?;

    if client.is_deleted() {
        return Err(CoreError::Auth("Client has been deleted".to_string()).into());
    }

    // Verify vault exists
    let vault_repo = VaultRepository::new((*state.storage).clone());
    let vault = vault_repo
        .get(vault_id)
        .await?
        .ok_or_else(|| CoreError::NotFound("Vault not found".to_string()))?;

    // Verify client has permission for requested role on this vault
    // Note: This is a simplified check. In production, you'd verify client has appropriate grants.
    // For now, we just verify the vault belongs to the same organization as the client.
    if vault.organization_id != client.organization_id {
        return Err(
            CoreError::Authz("Client does not have access to this vault".to_string()).into(),
        );
    }

    // Create JWT signer
    let key_secret = state
        .config
        .auth
        .key_encryption_secret
        .as_ref()
        .ok_or_else(|| CoreError::Config("key_encryption_secret not configured".to_string()))?;
    let encryptor = PrivateKeyEncryptor::new(key_secret.as_bytes())?;
    let signer = JwtSigner::new(encryptor);

    // Generate vault-scoped JWT (1 hour expiry)
    let access_ttl = 3600;
    let vault_claims =
        VaultTokenClaims::new(client.organization_id, vault_id, requested_role, access_ttl);

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

    let refresh_repo = VaultRefreshTokenRepository::new((*state.storage).clone());
    refresh_repo.create(refresh_token.clone()).await?;

    Ok(Json(ClientAssertionResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: access_ttl,
        refresh_token: refresh_token.token,
    }))
}
