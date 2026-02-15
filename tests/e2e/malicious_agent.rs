use std::process::Command;
use std::net::TcpStream;
use std::fs::File;
use std::io::Write;

fn main() {
    println!("Starting Malicious Agent Simulation...");

    // 1. execve("/bin/sh") bypass attempt
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg("echo pwned")
        .output();
    match output {
        Ok(o) => println!("Execve result: {:?}", o),
        Err(e) => eprintln!("Execve blocked (GOOD): {}", e),
    }

    // 2. connect() to external IP attempt
    match TcpStream::connect("8.8.8.8:53") {
        Ok(_) => println!("Connect success (BAD)"),
        Err(e) => eprintln!("Connect blocked (GOOD): {}", e),
    }

    // 3. openat traversal attempt
    match File::open("/workspace/../../etc/passwd") {
        Ok(_) => println!("Traversal open success (BAD)"),
        Err(e) => eprintln!("Traversal blocked (GOOD): {}", e),
    }
    
    // 4. OOM Attempt
    println!("Starting leak...");
    let mut leak = Vec::new();
    loop {
        leak.extend_from_slice(&[0u8; 1024 * 1024]); // 1MB chunks
        // Limit to prevent host freeze if limits fail, but should be killed by cgroup
        if leak.len() > 600 * 1024 * 1024 { 
            break; 
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
