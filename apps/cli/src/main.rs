use clap::{Args, Parser, Subcommand};
use omni_api::{detect_default_frontend_dir, ApiConfig, AppState};
use omni_core::{DataPayload, ExecutionContext, FeatureStatus, OperationCategory};
use omni_pipeline::{PipelineDefinition, PipelineExecutionOptions, PipelineExecutor};
use omni_registry::{OperationRegistry, RegistryFilter};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Parser, Debug)]
#[command(
    name = "omni",
    author = "Rajveersinh Pardeshi <daveaddams91@gmail.com>",
    version = "0.1.0",
    about = "OMNI — The Universal Digital Engineering Toolkit",
    long_about = "A local-first, Rust-powered engineering, security, and forensics toolkit with typed DAG pipelines."
)]
struct Cli {
    #[arg(short, long, global = true, help = "Output machine-readable JSON")]
    json: bool,

    #[arg(
        short,
        long,
        global = true,
        help = "Write output to specified file instead of stdout"
    )]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "List registered operations with optional filtering")]
    List {
        #[arg(
            short,
            long,
            help = "Filter by category (e.g. Cryptography, Encoders, TextAndCode, Networking)"
        )]
        category: Option<String>,
        #[arg(short, long, help = "Search query across ID, name, description, and tags")]
        query: Option<String>,
        #[arg(
            short,
            long,
            help = "Filter by verification status (verified, implemented, experimental, unsupported)"
        )]
        status: Option<String>,
        #[arg(short, long, help = "Filter by exact tag")]
        tag: Option<String>,
    },

    #[command(about = "Show detailed manifest, limitations, and status for an operation")]
    Info {
        #[arg(help = "Operation identifier")]
        id: String,
    },

    #[command(about = "Export the machine-readable feature inventory report")]
    Inventory,

    #[command(about = "Execute any registered operation by ID")]
    Run(RunArgs),

    #[command(about = "Pipeline orchestration, validation, and execution")]
    Pipeline {
        #[command(subcommand)]
        subcmd: PipelineSubcommands,
    },

    #[command(about = "Universal encoding & decoding shortcut")]
    Encode {
        #[arg(help = "Format (base16, base32, base45, base58, base62, base64, base85, base91, url)")]
        format: String,
        #[arg(short, long, help = "Decode instead of encode")]
        decode: bool,
        #[arg(help = "Input file (reads from stdin if omitted)")]
        input: Option<PathBuf>,
    },

    #[command(about = "Start local backend REST/WebSocket API & Web UI server")]
    Serve {
        #[arg(short = 'H', long, default_value = "127.0.0.1", help = "Bind address")]
        host: String,
        #[arg(short, long, default_value_t = 8080, help = "Port number")]
        port: u16,
        #[arg(
            long,
            env = "OMNI_AUTH_TOKEN",
            help = "Bearer token required for API/WS access (mandatory for non-loopback binds)"
        )]
        auth_token: Option<String>,
        #[arg(
            long = "cors-origin",
            help = "Allowed CORS origin (may be repeated; defaults to loopback)"
        )]
        cors_origins: Vec<String>,
        #[arg(long, help = "Path to frontend static assets directory")]
        frontend_dir: Option<PathBuf>,
        #[arg(
            long,
            default_value_t = 16,
            help = "Maximum request body size in megabytes"
        )]
        max_body_mb: usize,
        #[arg(
            long,
            default_value_t = false,
            help = "Explicitly acknowledge binding to a non-loopback address without authentication"
        )]
        allow_unauthenticated_remote: bool,
    },
}

#[derive(Args, Debug)]
struct RunArgs {
    #[arg(help = "Operation ID (e.g. encode.base64, crypto.hash.sha256)")]
    operation_id: String,

    #[arg(help = "Input file path (reads from stdin if omitted)")]
    input: Option<PathBuf>,

    #[arg(short, long, help = "JSON configuration string for operation")]
    config: Option<String>,
}

#[derive(Subcommand, Debug)]
enum PipelineSubcommands {
    #[command(about = "Execute a pipeline JSON specification")]
    Run {
        #[arg(help = "Pipeline definition JSON file")]
        file: PathBuf,
        #[arg(help = "Initial input file (reads from stdin if omitted)")]
        input: Option<PathBuf>,
    },
    #[command(about = "Validate a pipeline DAG for cycles, multi-input rules, and type compatibility")]
    Validate {
        #[arg(help = "Pipeline definition JSON file")]
        file: PathBuf,
    },
}

fn read_input(path: Option<PathBuf>) -> io::Result<DataPayload> {
    if let Some(p) = path {
        let bytes = fs::read(p)?;
        match String::from_utf8(bytes) {
            Ok(s) => Ok(DataPayload::text(s)),
            Err(e) => Ok(DataPayload::bytes(e.into_bytes())),
        }
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        match String::from_utf8(buffer) {
            Ok(s) => Ok(DataPayload::text(s)),
            Err(e) => Ok(DataPayload::bytes(e.into_bytes())),
        }
    }
}

fn write_output(payload: DataPayload, output_path: Option<PathBuf>, json_mode: bool) -> io::Result<()> {
    if json_mode {
        let json = serde_json::to_string_pretty(&payload)?;
        if let Some(path) = output_path {
            fs::write(path, json.as_bytes())?;
        } else {
            println!("{}", json);
        }
    } else {
        let bytes = payload.into_bytes();
        if let Some(path) = output_path {
            fs::write(path, &bytes)?;
        } else {
            io::stdout().write_all(&bytes)?;
        }
    }
    Ok(())
}

fn build_full_registry() -> anyhow::Result<OperationRegistry> {
    let mut reg = OperationRegistry::new();
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
    Ok(reg)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let registry = Arc::new(RwLock::new(build_full_registry()?));

    match cli.command {
        Commands::List {
            category,
            query,
            status,
            tag,
        } => {
            let parsed_category = match category.as_deref() {
                Some(c) => match OperationCategory::from_str_loose(c) {
                    Some(cat) => Some(cat),
                    None => {
                        eprintln!(
                            "Error: Unknown category '{}'. Valid categories: Cryptography, Encoders, TextAndCode, DocumentsAndMedia, Networking, BinaryAnalysis, StorageAndFormats, CloudAndDevOps, AiAndTensors, SystemDiagnostics",
                            c
                        );
                        std::process::exit(1);
                    }
                },
                None => None,
            };

            let parsed_status = match status.as_deref() {
                Some(s) => match FeatureStatus::from_str_loose(s) {
                    Some(st) => Some(st),
                    None => {
                        eprintln!(
                            "Error: Unknown status '{}'. Valid statuses: planned, in_progress, experimental, implemented, verified, unsupported",
                            s
                        );
                        std::process::exit(1);
                    }
                },
                None => None,
            };

            let reg = registry
                .read()
                .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
            let manifests = reg.filter(&RegistryFilter {
                category: parsed_category,
                query: query.as_deref(),
                tag: tag.as_deref(),
                status: parsed_status,
                ..Default::default()
            });

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&manifests)?);
            } else {
                println!(
                    "{:<28} {:<14} {:<24} {:<32}",
                    "OPERATION ID", "STATUS", "CATEGORY", "NAME"
                );
                println!("{:-<100}", "");
                for m in &manifests {
                    println!(
                        "{:<28} {:<14} {:<24} {}",
                        m.id,
                        m.status.to_string(),
                        format!("{:?}", m.category),
                        m.name
                    );
                }
                println!("\nTotal matched: {} operations", manifests.len());
            }
        }

        Commands::Inventory => {
            let reg = registry
                .read()
                .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
            let report = reg.export_inventory();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("OMNI Machine-Readable Feature Inventory");
                println!("Total operations: {}", report.total_operations);
                println!("\nBy Status:");
                for (status, count) in &report.status_counts {
                    println!("  {:<15} {}", status, count);
                }
                println!("\nBy Category:");
                for (cat, count) in &report.category_counts {
                    println!("  {:<30} {}", cat, count);
                }
            }
        }

        Commands::Info { id } => {
            let reg = registry
                .read()
                .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
            if let Some(op) = reg.get(&id) {
                let m = op.manifest();
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&m)?);
                } else {
                    println!("ID:          {}", m.id);
                    println!("Name:        {}", m.name);
                    println!("Category:    {:?}", m.category);
                    println!("Status:      {}", m.status);
                    println!("Security:    {:?}", m.security_level);
                    println!("Multi-Input: {}", m.accepts_multi_input);
                    println!("Description: {}", m.description);
                    println!("Inputs:      {:?}", m.input_types);
                    println!("Outputs:     {:?}", m.output_types);
                    if !m.limitations.is_empty() {
                        println!("Limitations:");
                        for lim in &m.limitations {
                            println!("  - {}", lim);
                        }
                    }
                }
            } else {
                eprintln!("Error: Operation '{}' not found.", id);
                std::process::exit(1);
            }
        }

        Commands::Run(args) => {
            let input = read_input(args.input)?;
            let config: serde_json::Value = if let Some(c) = args.config {
                serde_json::from_str(&c)?
            } else {
                serde_json::json!({})
            };

            let op = {
                let reg = registry
                    .read()
                    .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
                reg.get(&args.operation_id)
            };

            if let Some(op) = op {
                let ctx = ExecutionContext::new("cli_run");
                match op.execute(input, config, &ctx).await {
                    Ok(output) => write_output(output, cli.output, cli.json)?,
                    Err(e) => {
                        eprintln!("Execution error: {}", e);
                        std::process::exit(1);
                    }
                }
            } else {
                eprintln!("Error: Operation '{}' not found.", args.operation_id);
                std::process::exit(1);
            }
        }

        Commands::Pipeline { subcmd } => match subcmd {
            PipelineSubcommands::Validate { file } => {
                let content = fs::read_to_string(file)?;
                let pipeline: PipelineDefinition = serde_json::from_str(&content)?;
                let reg = registry
                    .read()
                    .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
                match omni_pipeline::PipelineValidator::validate(&pipeline, &reg) {
                    Ok(order) => {
                        if cli.json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&serde_json::json!({
                                    "valid": true,
                                    "execution_order": order
                                }))?
                            );
                        } else {
                            println!("Pipeline is valid. Execution order: {:?}", order);
                        }
                    }
                    Err(e) => {
                        eprintln!("Pipeline validation error: {}", e);
                        std::process::exit(1);
                    }
                }
            }
            PipelineSubcommands::Run { file, input } => {
                let content = fs::read_to_string(file)?;
                let pipeline: PipelineDefinition = serde_json::from_str(&content)?;
                let initial_input = read_input(input)?;
                let ctx = ExecutionContext::new("cli_pipeline");
                let options = PipelineExecutionOptions {
                    max_concurrency: pipeline.max_concurrency.unwrap_or(4).max(1),
                    ..Default::default()
                };
                let report = PipelineExecutor::execute_with_report(
                    &pipeline,
                    initial_input,
                    &registry,
                    &ctx,
                    options,
                )
                .await?;

                if cli.json {
                    let output_json = serde_json::to_string_pretty(&report)?;
                    if let Some(path) = cli.output {
                        fs::write(path, output_json.as_bytes())?;
                    } else {
                        println!("{}", output_json);
                    }
                } else {
                    println!(
                        "Pipeline '{}' completed in {} ms (execution_id={}).",
                        report.pipeline_id, report.total_duration_ms, report.execution_id
                    );
                    for node in &report.nodes {
                        println!(
                            "  Node [{:<16}] ({:<24}) {:?} | {} ms | {} bytes",
                            node.node_id,
                            node.operation_id,
                            node.status,
                            node.duration_ms.unwrap_or(0),
                            node.output_bytes.unwrap_or(0)
                        );
                    }
                }
            }
        },

        Commands::Encode {
            format,
            decode,
            input,
        } => {
            let normalized_fmt = match format.to_lowercase().as_str() {
                "hex" => "base16",
                _ => format.as_str(),
            };
            let op_id = format!("encode.{}", normalized_fmt);
            let input_payload = read_input(input)?;
            let config = serde_json::json!({ "decode": decode });

            let op = {
                let reg = registry
                    .read()
                    .map_err(|e| anyhow::anyhow!("Registry lock poisoned: {e}"))?;
                reg.get(&op_id)
            };

            if let Some(op) = op {
                let ctx = ExecutionContext::new("cli_encode");
                let output = op.execute(input_payload, config, &ctx).await?;
                write_output(output, cli.output, cli.json)?;
            } else {
                eprintln!("Error: Encoder operation '{}' not found.", op_id);
                std::process::exit(1);
            }
        }

        Commands::Serve {
            host,
            port,
            auth_token,
            cors_origins,
            frontend_dir,
            max_body_mb,
            allow_unauthenticated_remote,
        } => {
            if !is_loopback_host(&host) && auth_token.is_none() && !allow_unauthenticated_remote {
                eprintln!(
                    "Security Error: Refusing to bind to non-loopback address '{}' without --auth-token (or OMNI_AUTH_TOKEN). Pass --auth-token <SECRET> or --allow-unauthenticated-remote to override explicitly.",
                    host
                );
                std::process::exit(1);
            }

            let db = Arc::new(omni_storage::DatabaseManager::open("omni.db")?);
            let job_manager = omni_workers::JobManager::new(registry.clone(), db.clone());

            let mut config = ApiConfig::for_loopback_port(port)
                .with_max_body_bytes(max_body_mb.saturating_mul(1024 * 1024));
            if let Some(tok) = auth_token {
                config = config.with_auth_token(tok);
            }
            if !cors_origins.is_empty() {
                config = config.with_allowed_origins(cors_origins);
            }
            if let Some(dir) = frontend_dir.or_else(detect_default_frontend_dir) {
                config = config.with_frontend_dir(dir);
            }

            let frontend_msg = config
                .frontend_dir
                .as_ref()
                .map(|p| format!("serving frontend from {}", p.display()))
                .unwrap_or_else(|| "API-only mode (no frontend/ directory found)".to_string());

            let state = AppState::new(registry.clone(), db, job_manager.clone(), config);
            let app = omni_api::create_router(state);
            let addr = format!("{}:{}", host, port);
            println!("OMNI Backend server listening on http://{} ({})", addr, frontend_msg);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            let jm_shutdown = job_manager.clone();
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let cancelled = jm_shutdown.shutdown();
                    eprintln!("\nShutting down OMNI server ({} active jobs cancelled)...", cancelled);
                })
                .await?;
        }
    }

    Ok(())
}
