// Placeholder for audit logging, kept as a compat shim with the
// box-fraise-server pattern (`audit::write` on the bare pool, outside
// any tx). Chat traffic is high-cardinality and mostly opaque, so
// the routine audit target here is server logs; DB audit is added
// when a specific compliance requirement arrives.

use serde_json::Value;
use uuid::Uuid;

#[allow(clippy::too_many_arguments)]
pub async fn write(
    _pool: &crate::db::Pool,
    actor_type: &str,
    actor_id: Option<Uuid>,
    action: &str,
    target: Option<&str>,
    payload: Value,
) {
    tracing::info!(
        actor_type,
        actor_id = actor_id.map(|u| u.to_string()),
        action,
        target,
        payload = %payload,
        "audit"
    );
}
