// End-to-end smoke test for the chat scaffold.
//
// Environment expectations (set before `cargo test`):
//   TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5433/fraise_chat
//   INTERNAL_SECRET=devsecret
//
// The test starts the app in-process with a canned identity verifier
// (via INTERNAL_SECRET + X-BF-User-Id) so it does not need a running
// box-fraise-server. It exercises:
//   1. Alice + Bob register prekey bundles.
//   2. Alice fetches Bob's bundle (consuming one of his OPKs).
//   3. Alice sends a prekey-envelope ciphertext to Bob.
//   4. Bob polls his pending queue and finds it.
//   5. Bob acks the message and the queue is empty.
//   6. Bob's OPK count decrements as expected.

use std::net::SocketAddr;

use base64::Engine;
use box_fraise_chat::{app, config::Config, db};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::json;
use uuid::Uuid;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

async fn start_server() -> (SocketAddr, String) {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5435/fraise_chat".into());
    let secret = "devsecret".to_string();
    let cfg = Config {
        database_url: database_url.clone(),
        port: 0,
        identity_base_url: "http://127.0.0.1:1".into(), // unreachable — must not be hit
        internal_secret: Some(secret.clone()),
    };
    let pool = db::connect(&database_url).await.expect("db connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");

    // Isolation is via unique Uuid::new_v4() user IDs per test — no
    // truncate needed. Accumulating rows over dev runs is fine.

    let state = app::AppState::new(pool, cfg);
    let router = app::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, secret)
}

fn internal_headers(secret: &str, user_id: Uuid) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("x-bf-internal", HeaderValue::from_str(secret).unwrap());
    h.insert(
        "x-bf-user-id",
        HeaderValue::from_str(&user_id.to_string()).unwrap(),
    );
    h
}

fn dummy_key(fill: u8) -> String {
    // 33 bytes: DjB point prefix (0x05) + 32 payload bytes.
    let mut v = vec![0x05];
    v.extend_from_slice(&[fill; 32]);
    B64.encode(v)
}
fn dummy_sig(fill: u8) -> String {
    B64.encode(vec![fill; 64])
}

fn bundle_body(reg_id: i32, ident: u8, spk: u8, sig: u8, opks: &[(i32, u8)]) -> serde_json::Value {
    json!({
        "registration_id": reg_id,
        "identity_key":    dummy_key(ident),
        "signed_prekey": {
            "key_id":     1,
            "public_key": dummy_key(spk),
            "signature":  dummy_sig(sig),
        },
        "one_time_prekeys": opks.iter().map(|(id, fill)| json!({
            "key_id": id, "public_key": dummy_key(*fill),
        })).collect::<Vec<_>>(),
    })
}

#[tokio::test]
async fn round_trip_send_and_receive() {
    let (addr, secret) = start_server().await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();

    // Alice registers.
    let r = client
        .post(format!("{base}/v1/keys/bundle"))
        .headers(internal_headers(&secret, alice))
        .json(&bundle_body(
            1001,
            0xAA,
            0xA1,
            0xA2,
            &[(11, 0xB1), (12, 0xB2)],
        ))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "alice register: {}", r.status());

    // Bob registers.
    let r = client
        .post(format!("{base}/v1/keys/bundle"))
        .headers(internal_headers(&secret, bob))
        .json(&bundle_body(
            2002,
            0xBB,
            0xB3,
            0xB4,
            &[(21, 0xC1), (22, 0xC2), (23, 0xC3)],
        ))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "bob register: {}", r.status());

    // Alice fetches Bob's bundle — consumes 1 OPK.
    let r = client
        .get(format!("{base}/v1/keys/of/{bob}"))
        .headers(internal_headers(&secret, alice))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let bundle: serde_json::Value = r.json().await.unwrap();
    assert_eq!(bundle["registration_id"], 2002);
    assert!(bundle["one_time_prekey"].is_object());

    // Alice sends Bob a message (envelope type 3 = prekey init).
    let ciphertext = B64.encode(b"opaque bytes only Bob can decrypt");
    let r = client
        .post(format!("{base}/v1/messages/to/{bob}"))
        .headers(internal_headers(&secret, alice))
        .json(&json!({ "envelope_type": 3, "ciphertext": ciphertext }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let sent: serde_json::Value = r.json().await.unwrap();
    let msg_id = sent["id"].as_str().unwrap().to_string();

    // Bob polls.
    let r = client
        .get(format!("{base}/v1/messages"))
        .headers(internal_headers(&secret, bob))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let pending: Vec<serde_json::Value> = r.json().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0]["sender_user_id"].as_str().unwrap(),
        alice.to_string()
    );
    assert_eq!(pending[0]["envelope_type"], 3);
    assert_eq!(pending[0]["ciphertext"], ciphertext);

    // Bob acks.
    let r = client
        .delete(format!("{base}/v1/messages/{msg_id}"))
        .headers(internal_headers(&secret, bob))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());

    // Queue empty.
    let r = client
        .get(format!("{base}/v1/messages"))
        .headers(internal_headers(&secret, bob))
        .send()
        .await
        .unwrap();
    let pending: Vec<serde_json::Value> = r.json().await.unwrap();
    assert!(pending.is_empty());

    // Bob's OPK count went from 3 down to 2.
    let r = client
        .get(format!("{base}/v1/keys/one-time"))
        .headers(internal_headers(&secret, bob))
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["unconsumed_one_time_prekeys"], 2);
}

#[tokio::test]
async fn sender_cannot_be_recipient() {
    let (addr, secret) = start_server().await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let alice = Uuid::new_v4();

    let r = client
        .post(format!("{base}/v1/keys/bundle"))
        .headers(internal_headers(&secret, alice))
        .json(&bundle_body(3003, 0x11, 0x12, 0x13, &[(1, 0x14)]))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());

    let r = client
        .post(format!("{base}/v1/messages/to/{alice}"))
        .headers(internal_headers(&secret, alice))
        .json(&json!({ "envelope_type": 1, "ciphertext": B64.encode(b"self") }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn rejects_bad_length_keys() {
    let (addr, secret) = start_server().await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    let alice = Uuid::new_v4();

    let body = json!({
        "registration_id": 4004,
        "identity_key":    B64.encode(b"too short"),
        "signed_prekey": {
            "key_id": 1,
            "public_key": dummy_key(0x01),
            "signature":  dummy_sig(0x02),
        },
        "one_time_prekeys": [],
    });
    let r = client
        .post(format!("{base}/v1/keys/bundle"))
        .headers(internal_headers(&secret, alice))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}
