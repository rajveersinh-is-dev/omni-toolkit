use omni_api::{detect_default_frontend_dir, ApiConfig, AppState};
use omni_registry::OperationRegistry;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

fn register_all_operations(registry: &Arc<RwLock<OperationRegistry>>) -> anyhow::Result<()> {
    let mut reg = registry
        .write()
        .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
    omni_encoders::register_encoders(&mut reg)?;
    omni_crypto::register_crypto(&mut reg)?;
    omni_text::register_text(&mut reg)?;
    omni_code::register_code(&mut reg)?;
    omni_documents::register_documents(&mut reg)?;
    omni_pdf::register_pdf(&mut reg)?;
    omni_media::register_media(&mut reg)?;
    omni_network::register_network(&mut reg)?;
    omni_pcap::register_pcap(&mut reg)?;
    omni_binary::register_binary(&mut reg)?;
    omni_firmware::register_firmware(&mut reg)?;
    omni_filesystems::register_filesystems(&mut reg)?;
    omni_infrastructure::register_infrastructure(&mut reg)?;
    omni_ai::register_ai(&mut reg)?;
    omni_system::register_system(&mut reg)?;
    omni_pipeline::register_pipeline_ops(&mut reg)?;
    Ok(())
}

struct DesktopArgs {
    headless: bool,
    port: u16,
    frontend_dir: Option<PathBuf>,
}

fn parse_args() -> DesktopArgs {
    let mut headless = false;
    let mut port = 8080u16;
    let mut frontend_dir = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--headless" => headless = true,
            "--port" => {
                if let Some(p) = args.next().and_then(|v| v.parse::<u16>().ok()) {
                    port = p;
                }
            }
            "--frontend-dir" => {
                if let Some(dir) = args.next() {
                    frontend_dir = Some(PathBuf::from(dir));
                }
            }
            _ => {}
        }
    }

    DesktopArgs {
        headless,
        port,
        frontend_dir,
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = parse_args();

    let registry = Arc::new(RwLock::new(OperationRegistry::new()));
    register_all_operations(&registry)?;

    let db = Arc::new(omni_storage::DatabaseManager::open("omni.db")?);
    let job_manager = omni_workers::JobManager::new(registry.clone(), db.clone());
    let frontend = args.frontend_dir.or_else(detect_default_frontend_dir);

    #[cfg(feature = "native-webview")]
    if !args.headless {
        return launch_native_window(registry, db, job_manager, frontend);
    }

    // Headless local web UI server mode (or default build without `native-webview` feature)
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let mut config = ApiConfig::for_loopback_port(args.port);
        if let Some(dir) = frontend {
            config = config.with_frontend_dir(dir);
        }

        let frontend_status = config
            .frontend_dir
            .as_ref()
            .map(|p| format!("serving frontend from {}", p.display()))
            .unwrap_or_else(|| "API-only (frontend/ directory not found)".to_string());

        let state = AppState::new(registry, db, job_manager.clone(), config);
        let app = omni_api::create_router(state);
        let addr = format!("127.0.0.1:{}", args.port);

        #[cfg(not(feature = "native-webview"))]
        println!(
            "OMNI Local Web UI Server (headless={}) running at http://{} ({}) — rebuild with `--features native-webview` for a native desktop window.",
            args.headless, addr, frontend_status
        );
        #[cfg(feature = "native-webview")]
        println!(
            "OMNI Headless Local Web UI Server running at http://{} ({})",
            addr, frontend_status
        );

        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let jm_shutdown = job_manager.clone();
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = tokio::signal::ctrl_c().await;
                let cancelled = jm_shutdown.shutdown();
                eprintln!("\nShutting down OMNI server ({} active jobs cancelled)...", cancelled);
            })
            .await?;
        Ok::<(), anyhow::Error>(())
    })
}

#[cfg(feature = "native-webview")]
fn launch_native_window(
    registry: Arc<RwLock<OperationRegistry>>,
    db: Arc<omni_storage::DatabaseManager>,
    job_manager: omni_workers::JobManager,
    frontend_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    use tao::{
        dpi::LogicalSize,
        event::{Event, WindowEvent},
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    };
    use tokio::sync::oneshot;
    use wry::WebViewBuilder;

    // Bind strictly to an ephemeral loopback port (127.0.0.1:0) with a per-launch session token
    let session_token = uuid::Uuid::new_v4().to_string();
    let (addr_tx, addr_rx) = std::sync::mpsc::channel::<Result<u16, String>>();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let jm_bg = job_manager.clone();
    let token_bg = session_token.clone();
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Runtime::new() {
            Ok(r) => r,
            Err(e) => {
                let _ = addr_tx.send(Err(e.to_string()));
                return;
            }
        };
        rt.block_on(async move {
            let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
                Ok(l) => l,
                Err(e) => {
                    let _ = addr_tx.send(Err(e.to_string()));
                    return;
                }
            };
            let bound_port = match listener.local_addr() {
                Ok(a) => a.port(),
                Err(e) => {
                    let _ = addr_tx.send(Err(e.to_string()));
                    return;
                }
            };

            let mut config = ApiConfig::for_loopback_port(bound_port).with_auth_token(token_bg);
            if let Some(dir) = frontend_dir {
                config = config.with_frontend_dir(dir);
            }
            let state = AppState::new(registry, db, jm_bg.clone(), config);
            let app = omni_api::create_router(state);

            let _ = addr_tx.send(Ok(bound_port));

            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                    let _ = jm_bg.shutdown();
                })
                .await;
        });
    });

    let bound_port = addr_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("Backend thread exited before binding loopback port"))?
        .map_err(|e| anyhow::anyhow!("Failed to bind local desktop backend: {e}"))?;

    let allowed_origin = format!("http://127.0.0.1:{}", bound_port);
    let entry_url = format!("{}/?token={}", allowed_origin, session_token);

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("OMNI — Universal Digital Engineering Toolkit")
        .with_inner_size(LogicalSize::new(1360.0, 860.0))
        .build(&event_loop)
        .map_err(|e| anyhow::anyhow!("Failed to create native desktop window: {e}"))?;

    let nav_origin = allowed_origin.clone();
    let _webview = WebViewBuilder::new()
        .with_url(&entry_url)
        .with_navigation_handler(move |url| {
            // Strictly prevent external navigation outside our local loopback origin
            url.starts_with(&nav_origin)
        })
        .build(&window)
        .map_err(|e| anyhow::anyhow!("Failed to initialize native WebView: {e}"))?;

    let mut shutdown_tx = Some(shutdown_tx);
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            if let Some(tx) = shutdown_tx.take() {
                let _ = tx.send(());
            }
            *control_flow = ControlFlow::Exit;
        }
    });
}
