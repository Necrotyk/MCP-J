use clap::Parser;
use mcp_j_engine::supervisor::Supervisor;
use mcp_j_engine::SandboxManifest;
use anyhow::Context;

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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, AsyncReadExt};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::signal::unix::{signal, SignalKind};

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
    
    mcp_j_engine::check_kernel_compatibility()?;

    let binary = std::path::PathBuf::from(&cli.command[0]);
    let args = cli.command[1..].to_vec();
    let project_root = std::env::current_dir()?;

    let mut manifest = if let Some(path) = &cli.manifest {
         let content = std::fs::read_to_string(path).context("Failed to read manifest")?;
         serde_json::from_str(&content).context("Failed to parse manifest")?
    } else {
         SandboxManifest::default()
    };
    
    // Enforce PATH and TERM defaults if omitted
    if !manifest.env_vars.contains_key("PATH") {
        manifest.env_vars.insert("PATH".to_string(), "/bin:/usr/bin".to_string());
    }
    if !manifest.env_vars.contains_key("TERM") {
        manifest.env_vars.insert("TERM".to_string(), "xterm-256color".to_string());
    }

    let supervisor = Supervisor::new(binary, args, project_root, manifest)?;
    let mut child = supervisor.spawn()?;

    let proxy = Arc::new(JsonRpcProxy::new());
    
    let child_stdin = child.stdin.take().expect("Child stdin missing");
    let child_stdout = child.stdout.take().expect("Child stdout missing");
    
    let async_child_stdin = tokio::fs::File::from_std(child_stdin);
    let async_child_stdout = tokio::fs::File::from_std(child_stdout);
    
    let host_stdin = tokio::io::stdin();

    async fn read_lsp_message<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> anyhow::Result<Option<Vec<u8>>> {
        let mut content_length = None;
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => return Ok(None),
                Ok(_) => {
                     if line == "\r\n" || line == "\n" {
                         break;
                     }
                     
                     let lower = line.to_lowercase();
                     if lower.starts_with("content-length:") {
                         if let Some(val) = lower.strip_prefix("content-length:") {
                             if let Ok(len) = val.trim().parse::<usize>() {
                                 content_length = Some(len);
                             }
                         }
                     }
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        if let Some(len) = content_length {
            const MAX_PAYLOAD_SIZE: usize = 5 * 1024 * 1024;
            if len > MAX_PAYLOAD_SIZE {
                return Err(anyhow::anyhow!(
                    "Payload size {} exceeds limit of {} bytes",
                    len,
                    MAX_PAYLOAD_SIZE
                ));
            }

            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            Ok(Some(buf))
        } else {
            Err(anyhow::anyhow!("Missing Content-Length header"))
        }
    }

    // Inbound Task: Host Stdin -> Proxy -> Child Stdin
    let proxy_in = proxy.clone();
    let mut reader_in = tokio::io::BufReader::new(host_stdin);
    let stdin_writer = Arc::new(Mutex::new(async_child_stdin));
    let stdin_writer_clone = stdin_writer.clone();

    let inbound_task = tokio::spawn(async move {
        loop {
            match read_lsp_message(&mut reader_in).await {
                Ok(Some(msg_bytes)) => {
                    let msg_str = match std::str::from_utf8(&msg_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                             tracing::error!(error = %e, "Invalid UTF-8 in LSP message");
                             continue;
                        }
                    };
                    
                    match proxy_in.validate_and_parse(msg_str) {
                        Ok(valid_req) => {
                             let mut child_stdin = stdin_writer_clone.lock().await;
                             let serialized = serde_json::to_string(&valid_req).unwrap();
                             let len = serialized.len();
                             let payload = format!("Content-Length: {}\r\n\r\n{}", len, serialized);
                             
                             if let Err(e) = child_stdin.write_all(payload.as_bytes()).await {
                                 tracing::error!(error = %e, "Failed to write to child stdin");
                                 break;
                             }
                             let _ = child_stdin.flush().await;
                        }
                        Err(rpc_err) => {
                             let serialized = serde_json::to_string(&rpc_err).unwrap();
                             let len = serialized.len();
                             let payload = format!("Content-Length: {}\r\n\r\n{}", len, serialized);
                             let mut stdout = tokio::io::stdout();
                             let _ = stdout.write_all(payload.as_bytes()).await;
                             let _ = stdout.flush().await;
                        }
                    }
                },
                Ok(None) => break,
                Err(e) => {
                    tracing::error!(error = %e, "Inbound LSP read error");
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Outbound Task: Child Stdout -> Proxy -> Host Stdout
    let proxy_out = proxy.clone();
    let mut reader_out = tokio::io::BufReader::new(async_child_stdout);
    
    let outbound_task = tokio::spawn(async move {
         loop {
            match read_lsp_message(&mut reader_out).await {
                Ok(Some(msg_bytes)) => {
                    let msg_str = match std::str::from_utf8(&msg_bytes) {
                        Ok(s) => s,
                        Err(e) => {
                             tracing::error!(error = %e, "Invalid UTF-8 in child outbound message");
                             continue;
                        }
                    };

                    match proxy_out.validate_and_parse(msg_str) {
                        Ok(valid_resp) => {
                             let serialized = serde_json::to_string(&valid_resp).unwrap();
                             let len = serialized.len();
                             let payload = format!("Content-Length: {}\r\n\r\n{}", len, serialized);
                             
                             let mut stdout = tokio::io::stdout();
                             if let Err(e) = stdout.write_all(payload.as_bytes()).await {
                                 tracing::error!(error = %e, "Failed to write to host stdout");
                                 break;
                             }
                             let _ = stdout.flush().await;
                        }
                        Err(e) => {
                             tracing::warn!(error = ?e, "Blocked outbound message from child");
                        }
                    }
                },
                Ok(None) => break,
                Err(e) => {
                    tracing::error!(error = %e, "Outbound LSP read error");
                    break; 
                }
            }
         }
        Ok::<(), anyhow::Error>(())
    });

    let child_pid = child.pid.as_raw();
    
    // Wait for child exit
    let wait_task = tokio::task::spawn_blocking(move || {
        child.wait()
    });
    
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = inbound_task => {
            tracing::debug!("Host stdin closed. Terminating.");
        },
        _ = outbound_task => {
            tracing::debug!("Child stdout closed. Terminating.");
        },
        res = wait_task => {
            match res {
                Ok(Ok(status)) => tracing::info!(status = ?status, "Child exited"),
                Ok(Err(e)) => tracing::error!(error = %e, "Wait failed"),
                Err(e) => tracing::error!(error = %e, "Join error"),
            }
        },
        _ = sigint.recv() => {
            tracing::warn!("SIGINT trapped. Executing strict teardown sequence.");
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(child_pid), nix::sys::signal::Signal::SIGKILL);
        },
        _ = sigterm.recv() => {
            tracing::warn!("SIGTERM trapped. Executing strict teardown sequence.");
            let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(child_pid), nix::sys::signal::Signal::SIGKILL);
        }
    }

    Ok(())
}
