use clap::Parser;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use std::{net::SocketAddr, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpStream, time};

use std::env;
use std::fs;
use std::path::PathBuf;
use directories::UserDirs;

#[derive(Parser, Debug)]
#[command(name = "clapscan", about = "Simple port scanner")]
struct Args {
    /// Target hostname or IP
    target: String,

    /// Ports "22,80,443" or "1-1024"
    #[arg(short = 'p', long = "ports", default_value = "1-1000")]
    ports: String,

    /// Concurrency, number of simultaneous connect tasks
    #[arg(short = 'c', long = "concurrency", default_value = "200")]
    concurrency: usize,

    /// Timeout per connect in milliseconds
    #[arg(long = "timeout-ms", default_value = "1000")]
    timeout_ms: u64,

    /// Output JSON
    #[arg(long = "json", default_value_t = false)]
    json: bool,
}

#[derive(Serialize)]
struct Finding {
    host: String,
    port: u16,
    status: &'static str,
    banner: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Handle install/uninstall flags before parsing args
    if env::args().any(|arg| arg == "--install") {
        return install_to_path().await;
    }
    if env::args().any(|arg| arg == "--uninstall") {
        return uninstall_from_path().await;
    }

    let args = Args::parse();

    let ports = parse_ports(&args.ports)?;
    let timeout = Duration::from_millis(args.timeout_ms);

    println!("Starting scan of {} ({} ports)...", args.target, ports.len());
    let ip = resolve_host(&args.target).await?;
    println!("Target IP: {}", ip);

    // Build tasks
    let tasks = ports.into_iter().map(|port| {
        let ip = ip;
        let timeout = timeout;
        async move {
            let addr = SocketAddr::new(ip, port);
            match time::timeout(timeout, TcpStream::connect(addr)).await {
                Ok(Ok(mut stream)) => {
                    // Try to read banner
                    let mut buf = [0u8; 128];
                    let banner = match time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            let cleaned = text
                                .chars()
                                .map(|c| if c.is_ascii() && !c.is_ascii_control() { c } else { '.' })
                                .collect::<String>()
                                .trim()
                                .to_string();
                            if cleaned.is_empty() { None } else { Some(cleaned) }
                        }
                        _ => None,
                    };
                    Some(Finding {
                        host: ip.to_string(),
                        port,
                        status: "open",
                        banner,
                    })
                }
                _ => None,
            }
        }
    });

    // Execute with bounded concurrency
    let results: Vec<Finding> = stream::iter(tasks)
        .buffer_unordered(args.concurrency)
        .filter_map(|x| async move { x })
        .collect()
        .await;

    // Output results
    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        let open_ports_count = results.len();
        println!("Scan completed! Found {} open ports:", open_ports_count);
        for r in &results {
            match &r.banner {
                Some(b) => println!("{}:{} open | {}", r.host, r.port, b),
                None => println!("{}:{} open", r.host, r.port),
            }
        }
        if results.is_empty() {
            println!("No open ports found");
        }
    }

    Ok(())
}

async fn install_to_path() -> anyhow::Result<()> {
    println!("Installing ClapScan to PATH...");
    
    // Get current executable path
    let current_exe = env::current_exe()?;
    
    // Get user's bin directory
    let user_dirs = UserDirs::new().ok_or_else(|| anyhow::anyhow!("Could not find user directories"))?;
    let home_dir = user_dirs.home_dir();
    let bin_dir = home_dir.join("bin");
    
    // Create bin directory if doesn't exist
    if !bin_dir.exists() {
        fs::create_dir_all(&bin_dir)?;
        println!("Created directory: {}", bin_dir.display());
    }
    
    // Copy executable to bin directory
    let target_path = bin_dir.join("clapscan");
    fs::copy(&current_exe, &target_path)?;
    
    println!("ClapScan installed successfully!");
    println!("Location: {}", target_path.display());
    println!("Example: clapscan google.com -p 80,443");
    println!("");
    println!("To uninstall, run: clapscan --uninstall");
    
    Ok(())
}

async fn uninstall_from_path() -> anyhow::Result<()> {
    println!("Uninstalling ClapScan from PATH...");
    
    let user_dirs = UserDirs::new().ok_or_else(|| anyhow::anyhow!("Could not find user directories"))?;
    let home_dir = user_dirs.home_dir();
    let target_path = home_dir.join("bin").join("clapscan.exe");
    
    if target_path.exists() {
        fs::remove_file(&target_path)?;
        println!("ClapScan uninstalled successfully!");
    } else {
        println!("ClapScan not found in PATH");
    }
    
    Ok(())
}

fn parse_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let p = part.trim();
        if p.contains('-') {
            let (a, b) = p.split_once('-').ok_or_else(|| anyhow::anyhow!("bad port range"))?;
            let a: u16 = a.trim().parse()?;
            let b: u16 = b.trim().parse()?;
            let start = a.min(b);
            let end = a.max(b);
            for port in start..=end {
                ports.push(port);
            }
        } else {
            ports.push(p.parse()?);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

async fn resolve_host(host: &str) -> anyhow::Result<std::net::IpAddr> {
    // Try to parse as IP first
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(ip);
    }
    
    // DNS lookup
    let addrs = tokio::net::lookup_host(format!("{}:0", host)).await?;
    for addr in addrs {
        return Ok(addr.ip());
    }
    
    Err(anyhow::anyhow!("Failed to resolve host: {}", host))
}