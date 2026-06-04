use clap::{Parser, Subcommand};
use serde::Deserialize;
use std::path::PathBuf;

use tuff_cse_core::digest::payload_digest_v0;
use tuff_cse_core::key_lifecycle::TuffKeyBundle;
use tuff_cse_core::profile::CseAlgTableV0;
use tuff_cse_txn::api::{cse_pre_recv, cse_pre_send};
use tuff_cse_txn::seal::RealKeyCseSealEngine;
use tuff_cse_txn::{CseFailMode, CseProfileId, CseTxContext};

#[derive(Parser)]
#[command(name = "cse_txn")]
#[command(about = "Public CSE+ verifier CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize local demo state.
    Init {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Show current status.
    Status,
    /// Run an internal self-test.
    Selftest,
    /// Run Known Answer Tests from JSON.
    Kat {
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Verify a raw packet.
    Verify {
        #[arg(short, long)]
        packet_hex: String,
    },
}

#[derive(Deserialize, Debug)]
struct KatTestCase {
    schema: String,
    payload_hex: String,
    expected: KatExpected,
}

#[derive(Deserialize, Debug)]
struct KatExpected {
    payload_digest: String,
    packet_hex: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Init { config } => {
            println!("Initializing public CSE+ line...");
            println!(
                "Config: {:?}",
                config.as_ref().unwrap_or(&PathBuf::from("default.conf"))
            );
            println!("Status: READY");
        }
        Commands::Status => {
            println!("Public Standard CSE verifier");
            println!("Status: RUNNING");
            println!("Line: CSE+");
            println!("Reference adapter: available");
        }
        Commands::Selftest => run_selftest()?,
        Commands::Kat { file } => run_kat(file)?,
        Commands::Verify { packet_hex } => {
            let data = hex::decode(packet_hex)?;
            let engine = demo_engine();

            match cse_pre_recv(&data, &engine) {
                Ok(verified) => {
                    println!("Verification SUCCESS");
                    println!("Tx ID: {:02x?}", verified.tx_id);
                    println!("Intent: {}", verified.intent_tag);
                }
                Err(e) => {
                    println!("Verification FAILED: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

fn demo_engine() -> RealKeyCseSealEngine {
    let alg_table = CseAlgTableV0::new_mock([1; 16], 1);
    let keys = TuffKeyBundle::from_components(&[1; 32], &[2; 32], &[3; 32]);
    RealKeyCseSealEngine { alg_table, keys }
}

fn demo_context() -> CseTxContext {
    CseTxContext {
        profile: CseProfileId::CsePlusStandard,
        facility_id_digest: [0xAA; 16],
        actor_id_digest: [0xBB; 16],
        session_id: [0xCC; 16],
        source_system: 1,
        destination_system: 2,
        route_id: 10,
        intent_tag: 101,
        risk_tag: 0,
        amount_bytes: None,
        beneficiary_bytes: None,
        key_id: [0xDD; 16],
        key_epoch: 1,
        fail_mode: CseFailMode::Reject,
        policy_digest: [0; 32],
    }
}

fn run_selftest() -> Result<(), Box<dyn std::error::Error>> {
    println!("Running public CSE+ self-test...");

    let engine = demo_engine();
    let ctx = demo_context();
    let payload = b"SELFTEST PAYLOAD";

    let output = cse_pre_send(ctx, payload, None, &engine)?;
    let verified = cse_pre_recv(&output.packet, &engine)?;
    assert_eq!(verified.payload_digest, payload_digest_v0(payload).0);

    println!("Self-test OK");
    Ok(())
}

fn run_kat(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("Loading Known Answer Test: {:?}", path);
    let content = std::fs::read_to_string(path)?;
    let tests: Vec<KatTestCase> = serde_json::from_str(&content)?;

    let engine = demo_engine();

    for (i, tc) in tests.iter().enumerate() {
        println!("Test Case {}: schema={}", i, tc.schema);

        let payload = hex::decode(&tc.payload_hex)?;
        let expected_digest = hex::decode(&tc.expected.payload_digest)?;
        let actual_digest = payload_digest_v0(&payload);

        if actual_digest.0 != expected_digest.as_slice() {
            println!("  [FAIL] Payload digest mismatch");
            continue;
        }

        let packet_data = hex::decode(&tc.expected.packet_hex)?;
        match cse_pre_recv(&packet_data, &engine) {
            Ok(verified) => {
                println!("  [OK] Verification passed");
                assert_eq!(verified.payload_digest, actual_digest.0);
            }
            Err(e) => {
                println!("  [FAIL] Verification error: {}", e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_engine_roundtrip() {
        let engine = demo_engine();
        let ctx = demo_context();
        let output = cse_pre_send(ctx, b"payload", None, &engine).unwrap();
        let verified = cse_pre_recv(&output.packet, &engine).unwrap();
        assert_eq!(verified.payload_digest, payload_digest_v0(b"payload").0);
    }
}
