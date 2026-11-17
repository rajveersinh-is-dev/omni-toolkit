use omni_registry::OperationRegistry;
use std::sync::{Arc, RwLock};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let registry = Arc::new(RwLock::new(OperationRegistry::new()));
    {
        let mut reg = registry.write().unwrap();
        let _ = omni_encoders::register_encoders(&mut reg);
        let _ = omni_crypto::register_crypto(&mut reg);
        let _ = omni_text::register_text(&mut reg);
        let _ = omni_code::register_code(&mut reg);
        let _ = omni_documents::register_documents(&mut reg);
        let _ = omni_pdf::register_pdf(&mut reg);
        let _ = omni_media::register_media(&mut reg);
        let _ = omni_network::register_network(&mut reg);
        let _ = omni_pcap::register_pcap(&mut reg);
        let _ = omni_binary::register_binary(&mut reg);
        let _ = omni_firmware::register_firmware(&mut reg);
        let _ = omni_filesystems::register_filesystems(&mut reg);
        let _ = omni_infrastructure::register_infrastructure(&mut reg);
        let _ = omni_ai::register_ai(&mut reg);
        let _ = omni_system::register_system(&mut reg);
    }
    let db = Arc::new(omni_storage::DatabaseManager::open("omni.db")?);
    let job_manager = omni_workers::JobManager::new(registry.clone(), db.clone());

    let state = omni_api::AppState {
        registry,
        db,
        job_manager,
    };

    let app = omni_api::create_router(state);
    let addr = "127.0.0.1:8080";
    println!("OMNI Desktop Application Backend starting on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
