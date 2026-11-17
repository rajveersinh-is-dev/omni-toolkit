use clap::{Args, Parser, Subcommand};
use omni_core::{DataPayload, ExecutionContext};
use omni_pipeline::{PipelineDefinition, PipelineExecutor};
use omni_registry::OperationRegistry;
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
    long_about = "A high-performance, local-first Swiss Army knife for developers, engineers, and digital forensics practitioners."
)]
struct Cli {
    #[arg(short, long, help = "Output machine-readable JSON")]
    json: bool,

    #[arg(short, long, help = "Write output to specified file instead of stdout")]
    output: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(about = "List all registered operations")]
    List {
        #[arg(short, long, help = "Filter by category")]
        category: Option<String>,
        #[arg(short, long, help = "Search query")]
        query: Option<String>,
    },

    #[command(about = "Show detailed manifest and usage for an operation")]
    Info {
        #[arg(help = "Operation identifier")]
        id: String,
    },

    #[command(about = "Execute any registered operation by ID")]
    Run(RunArgs),

    #[command(about = "Pipeline orchestration and execution")]
    Pipeline {
        #[command(subcommand)]
        subcmd: PipelineSubcommands,
    },

    #[command(about = "Universal encoding & decoding")]
    Encode {
        #[arg(help = "Format (base64, hex, base58, url, etc.)")]
        format: String,
        #[arg(short, long, help = "Decode instead of encode")]
        decode: bool,
        #[arg(help = "Input file (reads from stdin if omitted)")]
        input: Option<PathBuf>,
    },

    #[command(about = "Start local backend API & Web UI server")]
    Serve {
        #[arg(short, long, default_value = "127.0.0.1", help = "Bind address")]
        host: String,
        #[arg(short, long, default_value_t = 8080, help = "Port number")]
        port: u16,
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
    #[command(about = "Validate a pipeline DAG for cycles and type compatibility")]
    Validate {
        #[arg(help = "Pipeline definition JSON file")]
        file: PathBuf,
    },
}

fn read_input(file: Option<PathBuf>) -> io::Result<DataPayload> {
    if let Some(path) = file {
        let bytes = fs::read(&path)?;
        Ok(DataPayload::bytes(bytes))
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer)?;
        Ok(DataPayload::bytes(buffer))
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let registry = Arc::new(RwLock::new(OperationRegistry::new()));
    {
        let mut reg = registry.write().unwrap();
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
    }
    match cli.command {
        Commands::List { category, query } => {
            let reg = registry.read().unwrap();
            let manifests = if let Some(q) = query {
                reg.search(&q)
            } else if let Some(_cat) = category {
                reg.list_manifests()
            } else {
                reg.list_manifests()
            };

            if cli.json {
                println!("{}", serde_json::to_string_pretty(&manifests)?);
            } else {
                println!("{:<28} {:<24} {:<30}", "OPERATION ID", "NAME", "CATEGORY");
                println!("{:-<85}", "");
                for m in manifests {
                    println!("{:<28} {:<24} {:<30}", m.id, m.name, format!("{:?}", m.category));
                }
            }
        }

        Commands::Info { id } => {
            let reg = registry.read().unwrap();
            if let Some(op) = reg.get(&id) {
                let m = op.manifest();
                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&m)?);
                } else {
                    println!("ID:          {}", m.id);
                    println!("Name:        {}", m.name);
                    println!("Category:    {:?}", m.category);
                    println!("Description: {}", m.description);
                    println!("Inputs:      {:?}", m.input_types);
                    println!("Outputs:     {:?}", m.output_types);
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
                let reg = registry.read().unwrap();
                reg.get(&args.operation_id)
            };

            if let Some(op) = op {
                let ctx = ExecutionContext::new("cli_run");
                let output = op.execute(input, config, &ctx).await?;
                write_output(output, cli.output, cli.json)?;
            } else {
                eprintln!("Error: Operation '{}' not found.", args.operation_id);
                std::process::exit(1);
            }
        }

        Commands::Pipeline { subcmd } => match subcmd {
            PipelineSubcommands::Validate { file } => {
                let content = fs::read_to_string(file)?;
                let pipeline: PipelineDefinition = serde_json::from_str(&content)?;
                let reg = registry.read().unwrap();
                match omni_pipeline::PipelineValidator::validate(&pipeline, &reg) {
                    Ok(order) => {
                        println!("Pipeline is valid. Execution order: {:?}", order);
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
                let outputs = PipelineExecutor::execute(&pipeline, initial_input, &registry, &ctx).await?;

                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&outputs)?);
                } else {
                    println!("Pipeline execution completed successfully.");
                    for (node_id, payload) in outputs {
                        println!("Node [{}]: {} bytes output", node_id, payload.size_bytes());
                    }
                }
            }
        },

        Commands::Encode { format, decode, input } => {
            let op_id = format!("encode.{}", format);
            let input_payload = read_input(input)?;
            let config = serde_json::json!({ "decode": decode });

            let op = {
                let reg = registry.read().unwrap();
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

        Commands::Serve { host, port } => {
            let db = Arc::new(omni_storage::DatabaseManager::open("omni.db")?);
            let job_manager = omni_workers::JobManager::new(registry.clone(), db.clone());
            let state = omni_api::AppState {
                registry: registry.clone(),
                db,
                job_manager,
            };

            let app = omni_api::create_router(state);
            let addr = format!("{}:{}", host, port);
            println!("OMNI Backend API server listening on http://{}", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
