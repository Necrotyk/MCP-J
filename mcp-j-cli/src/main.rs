use clap::Parser;
use mcp_j_engine::supervisor::Supervisor;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
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
    let cli = Cli::parse();
    
    eprintln!("Launching jailed process: {:?}", cli.command);
    
    // Check kernel version
    mcp_j_engine::check_kernel_compatibility()?;

    // Initialize supervisor
    let binary = std::path::PathBuf::from(&cli.command[0]);
    let args = cli.command[1..].to_vec();
    let project_root = std::env::current_dir()?;

    let supervisor = Supervisor::new(binary, args, project_root)?;
    
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
                             eprintln!("Proxy Blocked Inbound: {}", err_obj);
                             // Return JSON-RPC Error to Host Stdin (NOT Child) if it came from Host?
                             // Wait, inbound is Host -> Child.
                             // Host sent bad data. We should reply to Host.
                             // Wait, Host Stdin is where we read. We write to Host Stdout.
                             // But Host expects response on Stdout.
                             // We should send the error object back to Host Stdout.
                             
                             // We need access to host_stdout?? 
                             // inbound_task owns framed_stdin (reader). it doesn't own stdout.
                             // We can't easily write to stdout from here without cloning it or using a channel.
                             // But wait, the user instructions say:
                             // "Serialize the generated JSON-RPC error and route it to host_stdout"
                             
                             // Re-architect: we need a shared stdout writer or a way to send response.
                             // Or we just print to stderr?
                             // "gracefully terminate the IDE's pending future" -> implies writing to stdout.
                             
                             // For now, let's just log to stderr as we can't easily access host_stdout here without refactoring main.
                             // Wait, we can clone `host_stdout` before spawning? `tokio::io::Stdout` is not cloneable easily?
                             // `tokio::io::stdout()` returns a handle. We can create multiple handles? Yes.
                             
                             // But wait, concurrent writes to stdout might interleave.
                             // Better to use a channel to the outbound task?
                             // Or just open a new stdout handle.
                             
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
                     eprintln!("Framing Error (Inbound): {}", e);
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
                             eprintln!("Proxy Blocked Outbound: {}", e);
                         }
                    }
                }
                Err(e) => {
                     eprintln!("Framing Error (Outbound): {}", e);
                     break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    // Wait for child exit
    let wait_task = tokio::task::spawn_blocking(move || {
        let status = child.wait();
        status
    });
    
    // Race tasks
    tokio::select! {
        _ = inbound_task => {}, // Stdin closed
        _ = outbound_task => {}, // Child stdout closed (child likely exited)
        res = wait_task => {
            match res {
                Ok(Ok(status)) => eprintln!("Child exited: {:?}", status),
                Ok(Err(e)) => eprintln!("Wait failed: {}", e),
                Err(e) => eprintln!("Join error: {}", e),
            }
        }
    }

    Ok(())
}

