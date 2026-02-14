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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    eprintln!("Launching jailed process: {:?}", cli.command);
    
    // Check kernel version
    mcp_j_engine::check_kernel_compatibility()?;

    // Initialize supervisor
    let binary = std::path::PathBuf::from(&cli.command[0]);
    let args = cli.command[1..].to_vec();

    let supervisor = Supervisor::new(binary, args)?;
    
    // Spawn child
    let mut child = supervisor.spawn()?;

    // Setup Proxy
    // We use Arc to share the proxy validator between tasks
    let proxy = Arc::new(JsonRpcProxy::new());
    
    // Convert std files to tokio files
    let child_stdin = child.stdin.take().expect("Child stdin missing");
    let child_stdout = child.stdout.take().expect("Child stdout missing");
    
    let mut async_child_stdin = tokio::fs::File::from_std(child_stdin);
    let async_child_stdout = tokio::fs::File::from_std(child_stdout);
    let mut async_child_stdout_reader = BufReader::new(async_child_stdout);
    
    let mut host_stdin_reader = BufReader::new(tokio::io::stdin());
    let mut host_stdout = tokio::io::stdout();

    // Inbound Task: Host Stdin -> Proxy -> Child Stdin
    let proxy_in = proxy.clone();
    let inbound_task = tokio::spawn(async move {
        let mut line = String::new();
        while host_stdin_reader.read_line(&mut line).await? > 0 {
            match proxy_in.validate_and_parse(&line) {
                Ok(_) => {
                    // Validated, forward raw line
                    async_child_stdin.write_all(line.as_bytes()).await?;
                    async_child_stdin.flush().await?;
                }
                Err(e) => {
                    eprintln!("Proxy Blocked Inbound: {}", e);
                }
            }
            line.clear();
        }
        Ok::<(), anyhow::Error>(())
    });

    // Outbound Task: Child Stdout -> Proxy -> Host Stdout
    let proxy_out = proxy.clone();
    let outbound_task = tokio::spawn(async move {
        let mut line = String::new();
        while async_child_stdout_reader.read_line(&mut line).await? > 0 {
            match proxy_out.validate_and_parse(&line) {
                Ok(_) => {
                    host_stdout.write_all(line.as_bytes()).await?;
                    host_stdout.flush().await?;
                }
                Err(e) => {
                    eprintln!("Proxy Blocked Outbound: {}", e);
                }
            }
            line.clear();
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

