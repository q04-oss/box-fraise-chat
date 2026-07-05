use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::app::AppState;
use crate::error::AppError;

/// AuthedUser resolves the Authorization header via the identity
/// service (or the internal escape-hatch header pair) and hands the
/// caller the user_id. Any handler that takes this in its signature
/// is guaranteed to run under a real, upstream-verified user.
pub struct AuthedUser(pub Uuid);

impl FromRequestParts<AppState> for AuthedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Internal escape hatch (tests, sidecar traffic).
        if let (Some(secret), Some(user_hdr)) = (
            parts
                .headers
                .get("x-bf-internal")
                .and_then(|v| v.to_str().ok()),
            parts
                .headers
                .get("x-bf-user-id")
                .and_then(|v| v.to_str().ok()),
        ) {
            return state
                .verifier
                .resolve_internal(secret, user_hdr)
                .map(AuthedUser);
        }

        let token = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(AppError::Unauthorized)?;

        state.verifier.resolve(token).await.map(AuthedUser)
    }
}
