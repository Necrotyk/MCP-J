use clap::Parser;
use mcp_j_engine::supervisor::Supervisor;
use mcp_j_engine::SandboxManifest;
use anyhow::{Context};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Path to execution manifest (JSON)
    #[arg(long, short)]
    manifest: Option<std::path::PathBuf>,

    /// Command to execute in the jail
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

use mcp_j_proxy::JsonRpcProxy;
use std::sync::Arc;
use tokio_util::codec::{FramedRead, LinesCodec};
use tokio::io::AsyncWriteExt;
use futures::StreamExt; // For .next()

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cli = Cli::parse();
    
    tracing::info!(command = ?cli.command, "Launching jailed process");
    
    // Check kernel version
    mcp_j_engine::check_kernel_compatibility()?;

    // Initialize supervisor
    let binary = std::path::PathBuf::from(&cli.command[0]);
    let args = cli.command[1..].to_vec();
    let project_root = std::env::current_dir()?;

    // Parse manifest or use default
    let mut manifest = if let Some(path) = &cli.manifest {
         let content = std::fs::read_to_string(path).context("Failed to read manifest")?;
         serde_json::from_str(&content).context("Failed to parse manifest")?
    } else {
         SandboxManifest::default()
    };
    
    // Ensure PATH and TERM are present if env_vars is empty or missing them
    if !manifest.env_vars.contains_key("PATH") {
        manifest.env_vars.insert("PATH".to_string(), "/bin:/usr/bin".to_string());
    }
    if !manifest.env_vars.contains_key("TERM") {
        manifest.env_vars.insert("TERM".to_string(), "xterm-256color".to_string());
    }

    let supervisor = Supervisor::new(binary, args, project_root, manifest)?;
    
    // Spawn child
    let mut child = supervisor.spawn()?;

    // Setup Proxy
    let proxy = Arc::new(JsonRpcProxy::new());
    
    // Convert std files to tokio files
    let child_stdin = child.stdin.take().expect("Child stdin missing");
    let child_stdout = child.stdout.take().expect("Child stdout missing");
    
    let mut async_child_stdin = tokio::fs::File::from_std(child_stdin);
    let async_child_stdout = tokio::fs::File::from_std(child_stdout);
    
    let host_stdin = tokio::io::stdin();
    let mut host_stdout = tokio::io::stdout();

    // Use strict memory bounding: 5MB max payload
    let max_length = 5 * 1024 * 1024;

    // Inbound Task: Host Stdin -> Proxy -> Child Stdin
    let proxy_in = proxy.clone();
    let inbound_task = tokio::spawn(async move {
        let codec = LinesCodec::new_with_max_length(max_length);
        let mut framed_stdin = FramedRead::new(host_stdin, codec);

        while let Some(line_result) = framed_stdin.next().await {
            match line_result {
                Ok(line) => {
                    match proxy_in.validate_and_parse(&line) {
                        Ok(v) => {
                             // Serialize back to raw line
                             // Wait, validation returns Value, we could re-serialize
                             // or just forward the original string if clean.
                             // `validate_and_parse` parses to Value.
                             // To be safe and canonical, let's re-serialize.
                             let mut raw = serde_json::to_string(&v)?;
                             raw.push('\n');
                             async_child_stdin.write_all(raw.as_bytes()).await?;
                             async_child_stdin.flush().await?;
                        }
                        Err(err_obj) => {
                             tracing::warn!(error = ?err_obj, "Proxy Blocked Inbound");
                             
                             let mut stdout = tokio::io::stdout();
                             let mut raw = serde_json::to_string(&err_obj).unwrap_or_default();
                             raw.push('\n');
                             // We ignore errors here
                             let _ = stdout.write_all(raw.as_bytes()).await;
                             let _ = stdout.flush().await;
                        }
                    }
                }
                Err(e) => {
                     tracing::error!(error = %e, "Framing Error (Inbound)");
                     break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Outbound Task: Child Stdout -> Proxy -> Host Stdout
    let proxy_out = proxy.clone();
    let outbound_task = tokio::spawn(async move {
        let codec = LinesCodec::new_with_max_length(max_length);
        let mut framed_child_stdout = FramedRead::new(async_child_stdout, codec);

        while let Some(line_result) = framed_child_stdout.next().await {
            match line_result {
                Ok(line) => {
                    match proxy_out.validate_and_parse(&line) {
                         Ok(v) => {
                             // Re-serialize strictly
                             let mut raw = serde_json::to_string(&v)?;
                             raw.push('\n');
                             host_stdout.write_all(raw.as_bytes()).await?;
                             host_stdout.flush().await?;
                         }
                         Err(e) => {
                             tracing::warn!(error = %e, "Proxy Blocked Outbound");
                         }
                    }
                }
                Err(e) => {
                     tracing::error!(error = %e, "Framing Error (Outbound)");
                     break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Wait for child exit
    let wait_task = tokio::task::spawn_blocking(move || {
        child.wait()
    });
    
    // Race tasks
    tokio::select! {
        _ = inbound_task => {}, // Stdin closed
        _ = outbound_task => {}, // Child stdout closed (child likely exited)
        res = wait_task => {
            match res {
                Ok(Ok(status)) => tracing::info!(status = ?status, "Child exited"),
                Ok(Err(e)) => tracing::error!(error = %e, "Wait failed"),
                Err(e) => tracing::error!(error = %e, "Join error"),
            }
        }
    }

    Ok(())
}

