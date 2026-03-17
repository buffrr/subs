//! subs-prover - ZK prover for subs
//!
//! Generates STARK proofs for step and fold operations, and SNARK compression.
//! Designed to run on GPU-enabled machines separate from the main subs operator.
//!
//! # Usage
//!
//! Prove a request:
//! ```bash
//! subs-prover prove -i request.json -o receipt.bin
//! ```
//!
//! Compress to SNARK:
//! ```bash
//! subs-prover compress -i compress_input.json -o snark.bin
//! ```
//!
//! Run as worker (polls endpoint for requests):
//! ```bash
//! subs-prover worker --url http://localhost:3000 --space @example
//! ```

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use subs_prover::Prover;
use subs_types::{CompressInput, ProvingRequest};

#[derive(Parser)]
#[command(
    name = "subs-prover",
    about = "ZK prover for subs - generates STARK/SNARK proofs",
    version
)]
struct Cli {
    /// Run as a server that accepts proving requests via HTTP
    #[arg(long)]
    server: bool,

    /// Server port (for --server mode)
    #[arg(long, default_value = "8888")]
    server_port: u16,

    /// Run as a worker that polls subsd for proving requests (auto-discovers all spaces)
    #[arg(long)]
    worker: bool,

    /// Base URL of the subsd server (for --worker mode)
    #[arg(short, long, default_value = "http://localhost:7777")]
    url: String,

    /// Poll interval in seconds when no work available (for --worker mode)
    #[arg(long, default_value = "5")]
    poll_interval: u64,

    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Prove a ProvingRequest (Step or Fold)
    Prove {
        /// Input file (JSON ProvingRequest). If not provided, reads from stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file for receipt. If not provided, writes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Compress a STARK proof to SNARK (Groth16)
    Compress {
        /// Input file (JSON CompressInput). If not provided, reads from stdin.
        #[arg(short, long)]
        input: Option<PathBuf>,
        /// Output file for receipt. If not provided, writes to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Benchmark: estimate proving cost for inserting handles into a tree
    Bench {
        /// Number of existing handles in the tree
        #[arg(long, default_value = "10000")]
        existing: usize,
        /// Number of new handles to insert
        #[arg(long, default_value = "100")]
        insert: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // --server flag takes precedence
    if cli.server {
        subs_prover::server::run_server(cli.server_port).await?;
        return Ok(());
    }

    // --worker flag
    if cli.worker {
        run_worker(&cli.url, cli.poll_interval).await?;
        return Ok(());
    }

    // Otherwise require a subcommand
    match cli.cmd {
        Some(Commands::Prove { input, output }) => {
            let input_data = read_input(input)?;
            let request: ProvingRequest = serde_json::from_slice(&input_data)?;
            let receipt = prove(&request)?;
            write_output(output, &receipt)?;
        }
        Some(Commands::Compress { input, output }) => {
            let input_data = read_input(input)?;
            let compress_input: CompressInput = serde_json::from_slice(&input_data)?;
            let receipt = compress(&compress_input)?;
            write_output(output, &receipt)?;
        }
        Some(Commands::Bench { existing, insert }) => {
            run_bench(existing, insert)?;
        }
        None => {
            eprintln!("Usage: subs-prover --server    (run as HTTP server)");
            eprintln!("       subs-prover --worker    (run as polling daemon)");
            eprintln!("       subs-prover prove       (prove single request)");
            eprintln!("       subs-prover compress    (compress to SNARK)");
            eprintln!("       subs-prover bench       (benchmark proving cost)");
            eprintln!();
            eprintln!("Run with --help for more options.");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn read_input(path: Option<PathBuf>) -> Result<Vec<u8>> {
    match path {
        Some(p) => Ok(fs::read(&p)?),
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            Ok(buf)
        }
    }
}

fn write_output(path: Option<PathBuf>, receipt: &[u8]) -> Result<()> {
    match path {
        Some(p) => {
            fs::write(&p, receipt)?;
            eprintln!("Receipt written to {}", p.display());
        }
        None => {
            io::stdout().write_all(receipt)?;
        }
    }
    Ok(())
}

fn prove(request: &ProvingRequest) -> Result<Vec<u8>> {
    let idx = request.idx();
    eprintln!("[#{}] Starting proof...", idx);
    let prover = Prover::new();
    let result = prover.prove(request);
    if result.is_ok() {
        eprintln!("[#{}] Proof complete.", idx);
    }
    result
}

fn compress(input: &CompressInput) -> Result<Vec<u8>> {
    eprintln!("Starting SNARK compression...");
    let prover = Prover::new();
    let result = prover.compress(input);
    if result.is_ok() {
        eprintln!("SNARK compression complete.");
    }
    result
}

fn run_bench(existing: usize, insert: usize) -> Result<()> {
    eprintln!("Building tree with {} existing handles, {} inserts...", existing, insert);
    let start = std::time::Instant::now();
    let request = subs_prover::build_bench_request(existing, insert)?;
    eprintln!("Request built in {:.2}s", start.elapsed().as_secs_f64());

    // Calibrate first
    eprintln!("\nCalibrating...");
    let prover = Prover::new();
    let calibration = match prover.calibrate() {
        Ok(info) => {
            eprintln!(
                "Calibration: {:.2}s per segment at po2={}\n",
                info.seconds_per_segment, info.calibration_po2
            );
            Some(info)
        }
        Err(e) => {
            eprintln!("Calibration failed: {}\n", e);
            None
        }
    };

    // Run estimate
    eprintln!("Estimating proof for {} handles inserted into tree of {}...", insert, existing);
    let estimate = prover.estimate(&request, calibration.as_ref())?;

    eprintln!("\n=== Estimate ===");
    eprintln!("Total user cycles:    {}", estimate.total_cycles);
    eprintln!("Total proving cycles: {} (padded)", estimate.total_proving_cycles);
    eprintln!("Segments:             {}", estimate.segments);
    for (i, seg) in estimate.segment_details.iter().enumerate() {
        let time_str = seg.estimated_seconds
            .map(|s| format!("{:.2}s", s))
            .unwrap_or_else(|| "n/a".into());
        eprintln!(
            "  Segment {}: {} user cycles, po2={}, est. {}",
            i, seg.cycles, seg.po2, time_str
        );
    }
    if let Some(total) = estimate.estimated_seconds {
        eprintln!("\nEstimated total proving time: {:.1}s", total);
    }

    Ok(())
}

/// Request type constants for binary fulfill payload
const REQUEST_TYPE_STEP: u8 = 0;
const REQUEST_TYPE_FOLD: u8 = 1;

/// Response from GET /spaces
#[derive(Deserialize)]
struct SpacesListResponse {
    spaces: Vec<String>,
}

/// Response from POST /spaces/{space}/proving/fulfill
#[derive(Deserialize)]
struct FulfillResponse {
    success: bool,
    message: Option<String>,
}

async fn run_worker(base_url: &str, poll_interval: u64) -> Result<()> {
    let client = reqwest::Client::new();
    let prover = Prover::new();

    eprintln!("Prover worker started");
    eprintln!("Connecting to: {}", base_url);
    eprintln!("Poll interval: {}s", poll_interval);

    eprintln!("Calibrating proving throughput...");
    match prover.calibrate() {
        Ok(info) => eprintln!(
            "Calibration complete: {:.2}s per segment at po2={}, {:.0} cycles/sec",
            info.seconds_per_segment, info.calibration_po2, info.cycles_per_sec
        ),
        Err(e) => eprintln!("Calibration failed: {}", e),
    }
    eprintln!();

    loop {
        // Get list of all spaces
        let spaces_url = format!("{}/spaces", base_url);
        let spaces = match client.get(&spaces_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<SpacesListResponse>().await {
                    Ok(list) => list.spaces,
                    Err(e) => {
                        eprintln!("Error parsing spaces list: {}", e);
                        tokio::time::sleep(Duration::from_secs(poll_interval)).await;
                        continue;
                    }
                }
            }
            Ok(resp) => {
                eprintln!("Error fetching spaces: {}", resp.status());
                tokio::time::sleep(Duration::from_secs(poll_interval)).await;
                continue;
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
                tokio::time::sleep(Duration::from_secs(poll_interval)).await;
                continue;
            }
        };

        if spaces.is_empty() {
            eprintln!("No spaces found. Waiting {}s...", poll_interval);
            tokio::time::sleep(Duration::from_secs(poll_interval)).await;
            continue;
        }

        let mut found_work = false;

        // Check each space for proving requests
        for space in &spaces {
            let next_url = format!("{}/spaces/{}/proving/next", base_url, urlencoding::encode(space));

            let response = match client
                .get(&next_url)
                .header("Accept", "application/octet-stream")
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[{}] Error fetching proving request: {}", space, e);
                    continue;
                }
            };

            if !response.status().is_success() {
                eprintln!("[{}] Error: {}", space, response.status());
                continue;
            }

            let bytes = match response.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[{}] Error reading response: {}", space, e);
                    continue;
                }
            };

            let request: Option<ProvingRequest> = match borsh::from_slice(&bytes) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[{}] Error deserializing: {}", space, e);
                    continue;
                }
            };

            let Some(request) = request else {
                continue; // No work for this space
            };

            found_work = true;

            let commitment_id = request.commitment_id();
            let idx = request.idx();
            let (kind, request_type) = match &request {
                ProvingRequest::Step { .. } => ("Step", REQUEST_TYPE_STEP),
                ProvingRequest::Fold { .. } => ("Fold", REQUEST_TYPE_FOLD),
            };

            eprintln!("[{}] #{} {} proof request (commitment_id={})", space, idx, kind, commitment_id);

            // Prove the request
            let receipt = match prover.prove(&request) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[{}] #{} Proving failed: {}", space, idx, e);
                    continue;
                }
            };

            eprintln!("[{}] #{} Proof complete ({} bytes). Submitting...", space, idx, receipt.len());

            // Build binary fulfill payload: commitment_id (8) + request_type (1) + receipt
            let mut payload = Vec::with_capacity(9 + receipt.len());
            payload.extend_from_slice(&commitment_id.to_le_bytes());
            payload.push(request_type);
            payload.extend_from_slice(&receipt);

            // Submit the receipt (binary)
            let fulfill_url = format!("{}/spaces/{}/proving/fulfill", base_url, urlencoding::encode(space));
            let response = match client
                .post(&fulfill_url)
                .header("Content-Type", "application/octet-stream")
                .body(payload)
                .send()
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("[{}] #{} Submit error: {}", space, idx, e);
                    continue;
                }
            };

            if response.status().is_success() {
                match response.json::<FulfillResponse>().await {
                    Ok(result) if result.success => {
                        eprintln!("[{}] #{} Receipt submitted successfully", space, idx);
                    }
                    Ok(result) => {
                        eprintln!("[{}] #{} Submit failed: {:?}", space, idx, result.message);
                    }
                    Err(e) => {
                        eprintln!("[{}] #{} Error parsing response: {}", space, idx, e);
                    }
                }
            } else {
                eprintln!("[{}] #{} Submit error: {}", space, idx, response.status());
            }

            eprintln!();
        }

        if !found_work {
            eprintln!("No pending proofs across {} space(s). Waiting {}s...", spaces.len(), poll_interval);
            tokio::time::sleep(Duration::from_secs(poll_interval)).await;
        }
    }
}
