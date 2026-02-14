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
    // We assume the first arg is the binary and the rest are args
    let binary = std::path::PathBuf::from(&cli.command[0]);
    let args = cli.command[1..].to_vec();

    // Create supervisor with the command
    let supervisor = match Supervisor::new(binary, args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize supervisor: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = supervisor.start() {
        eprintln!("Supervisor failed: {}", e);
        std::process::exit(1);
    }
}

