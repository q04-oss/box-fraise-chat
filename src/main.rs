use std::net::SocketAddr;

use anyhow::Context;
use box_fraise_chat::{app, config, db};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,box_fraise_chat=debug")),
        )
        .compact()
        .init();

    let cfg = config::Config::from_env().context("loading config")?;
    let pool = db::connect(&cfg.database_url).await.context("db connect")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("db migrate")?;

    let state = app::AppState::new(pool, cfg.clone());
    let router = app::build_router(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", cfg.port).parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!(?addr, "box-fraise-chat listening");
    axum::serve(listener, router).await?;
    Ok(())
}
