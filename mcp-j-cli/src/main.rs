use clap::Parser;
use mcp_j_engine::supervisor::Supervisor;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Command to execute in the jail
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    println!("Launching jailed process: {:?}", cli.command);

    // Initialize supervisor
    let supervisor = Supervisor::new();
    supervisor.run();
}
