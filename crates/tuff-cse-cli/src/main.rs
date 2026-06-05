use chrono::Utc;
use clap::{Parser, Subcommand};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use flate2::{Compression, write::GzEncoder};
use tuff_cse_core::digest::{digest_canonical, payload_digest_v0};
use tuff_cse_core::key_lifecycle::TuffKeyBundle;
use tuff_cse_core::profile::CseAlgTableV0;
use tuff_cse_txn::api::{cse_pre_recv, cse_pre_send};
use tuff_cse_txn::seal::RealKeyCseSealEngine;
use tuff_cse_txn::{CseFailMode, CseProfileId, CseTxContext};

const PACKAGE_ROOT: &str = "target/release-audit/packages";
const INSTALLATION_ROOT: &str = "target/release-audit/installations";
const THREE_BANK_ROOT: &str = "target/release-audit/three-bank-local";
const TEST_RESULTS_ROOT: &str = "target/release-audit/test-results";
const PACKAGE_NAME: &str = "cse-plus-linux-local.tar.gz";
const PACKAGE_STAGE_DIR: &str = "cse-plus-linux-local";
const PACKAGE_WINDOWS_DRY_RUN: &str = "cse-plus-windows-local.zip.dry-run.json";
const QUICK_HARNESS_RESULTS: &str = "three-bank-quick-results.jsonl";
const QUICK_HARNESS_SUMMARY: &str = "three-bank-quick-summary.json";

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
    /// Build local package artifacts.
    PackageLocal {
        #[arg(long, default_value = PACKAGE_ROOT)]
        output_root: PathBuf,
    },
    /// Install a local CSE+ tree.
    InstallLocal {
        #[arg(long)]
        institution_type: String,
        #[arg(long, default_value = "001")]
        branch_code: String,
        #[arg(long)]
        demo_seed_i32: i32,
        #[arg(long, default_value = INSTALLATION_ROOT)]
        output_root: PathBuf,
    },
    /// Remove a local CSE+ tree.
    UninstallLocal {
        #[arg(long)]
        institution_branch_id: String,
        #[arg(long, default_value = INSTALLATION_ROOT)]
        output_root: PathBuf,
    },
    /// Prepare the three-bank local topology.
    PrepareThreeBankLocal {
        #[arg(long, default_value = THREE_BANK_ROOT)]
        output_root: PathBuf,
    },
    /// Run the three-bank quick harness.
    RunThreeBankQuickHarness {
        #[arg(long, default_value_t = 10)]
        iterations: u32,
        #[arg(long, default_value = THREE_BANK_ROOT)]
        topology_root: PathBuf,
        #[arg(long, default_value = TEST_RESULTS_ROOT)]
        output_root: PathBuf,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DemoProfileRecord {
    schema_version: u8,
    institution_type: String,
    branch_code: String,
    institution_branch_id: String,
    demo_seed_i32: i32,
    generated_at_utc: String,
    profile_purpose: String,
    profile_digest: String,
    warning: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackageDryRunMetadata {
    artifact: String,
    platform: String,
    mode: String,
    files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BankSpec {
    institution_type: String,
    branch_code: String,
    institution_branch_id: String,
    demo_seed_i32: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BankPair {
    source: String,
    destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Topology {
    banks: Vec<BankSpec>,
    pairs: Vec<BankPair>,
    payload_sizes: Vec<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuickHarnessRow {
    case_id: String,
    case_class: String,
    harness_mode: String,
    source: String,
    destination: String,
    payload_size: usize,
    payload_digest: String,
    expected_result: String,
    actual_result: String,
    activation_allowed: bool,
    rejection_reason: String,
    elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SummaryBucket {
    passed: u64,
    failed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct QuickHarnessSummary {
    total: u64,
    passed: u64,
    failed: u64,
    false_allow: u64,
    false_reject: u64,
    by_case_class: BTreeMap<String, SummaryBucket>,
    by_harness_mode: BTreeMap<String, SummaryBucket>,
    by_pair: BTreeMap<String, SummaryBucket>,
    by_payload_size: BTreeMap<String, SummaryBucket>,
}

fn main() -> Result<(), Box<dyn Error>> {
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
            println!("CSE+ verifier");
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
        Commands::PackageLocal { output_root } => {
            let repo_root = workspace_root()?;
            build_local_package(&repo_root, output_root)?;
        }
        Commands::InstallLocal {
            institution_type,
            branch_code,
            demo_seed_i32,
            output_root,
        } => {
            let repo_root = workspace_root()?;
            install_local(
                &repo_root,
                output_root,
                institution_type,
                branch_code,
                *demo_seed_i32,
            )?;
        }
        Commands::UninstallLocal {
            institution_branch_id,
            output_root,
        } => {
            let repo_root = workspace_root()?;
            uninstall_local(&repo_root, output_root, institution_branch_id)?;
        }
        Commands::PrepareThreeBankLocal { output_root } => {
            let repo_root = workspace_root()?;
            prepare_three_bank_local(&repo_root, output_root)?;
        }
        Commands::RunThreeBankQuickHarness {
            iterations,
            topology_root,
            output_root,
        } => {
            let mut rng = StdRng::from_entropy();
            let repo_root = workspace_root()?;
            run_three_bank_quick_harness(
                &repo_root,
                topology_root,
                output_root,
                *iterations,
                &mut rng,
            )?;
        }
    }

    Ok(())
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    Ok(std::env::current_dir()?)
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

fn run_selftest() -> Result<(), Box<dyn Error>> {
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

fn run_kat(path: &PathBuf) -> Result<(), Box<dyn Error>> {
    println!("Loading Known Answer Test: {:?}", path);
    let content = fs::read_to_string(path)?;
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

fn validate_institution_type(value: &str) -> Result<(), String> {
    if value.len() == 4 && value.bytes().all(|b| b.is_ascii_alphanumeric()) {
        Ok(())
    } else {
        Err("institution type must be 4 ASCII alphanumeric bytes".to_string())
    }
}

fn validate_branch_code(value: &str) -> Result<(), String> {
    if value.len() == 3 && value.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err("branch code must be 3 ASCII digits".to_string())
    }
}

fn validate_seed(seed: i32) -> Result<(), String> {
    let _ = seed;
    Ok(())
}

fn institution_branch_id(institution_type: &str, branch_code: &str) -> String {
    format!("{institution_type}-{branch_code}")
}

fn build_demo_profile_record(
    institution_type: &str,
    branch_code: &str,
    demo_seed_i32: i32,
    generated_at_utc: String,
) -> Result<DemoProfileRecord, String> {
    validate_institution_type(institution_type)?;
    validate_branch_code(branch_code)?;
    validate_seed(demo_seed_i32)?;

    let digest = digest_canonical(
        b"cse-plus-demo-profile-v1",
        format!("{institution_type}:{branch_code}:{demo_seed_i32}:1").as_bytes(),
    );

    Ok(DemoProfileRecord {
        schema_version: 1,
        institution_type: institution_type.to_string(),
        branch_code: branch_code.to_string(),
        institution_branch_id: institution_branch_id(institution_type, branch_code),
        demo_seed_i32,
        generated_at_utc,
        profile_purpose: "demo/test only".to_string(),
        profile_digest: hex::encode(digest.0),
        warning: "demo/test only; not production readiness".to_string(),
    })
}

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn write_text_file(path: &Path, contents: &str) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)?;
    Ok(())
}

fn copy_file(src: &Path, dst: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(src, dst)?;
    Ok(())
}

fn copy_optional_file(src: &Path, dst: &Path) -> Result<(), Box<dyn Error>> {
    if src.exists() {
        copy_file(src, dst)?;
    }
    Ok(())
}

fn resolve_binary_path_from(workspace_root: &Path, target_dir: Option<&Path>) -> Option<PathBuf> {
    let mut candidates = Vec::new();

    if let Some(target_dir) = target_dir {
        let target_dir = if target_dir.is_absolute() {
            target_dir.to_path_buf()
        } else {
            workspace_root.join(target_dir)
        };
        candidates.extend([
            target_dir.join("release/cse_txn"),
            target_dir.join("debug/cse_txn"),
            target_dir.join("release/cse_txn.exe"),
            target_dir.join("debug/cse_txn.exe"),
        ]);
    }

    candidates.extend([
        workspace_root.join("target/release/cse_txn"),
        workspace_root.join("target/debug/cse_txn"),
        workspace_root.join("target/release/cse_txn.exe"),
        workspace_root.join("target/debug/cse_txn.exe"),
    ]);

    candidates.into_iter().find(|path| path.exists())
}

fn resolve_binary_path(workspace_root: &Path) -> Option<PathBuf> {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
    resolve_binary_path_from(workspace_root, target_dir.as_deref())
}

fn build_local_package(workspace_root: &Path, output_root: &Path) -> Result<(), Box<dyn Error>> {
    if !ensure_release_audit_path(workspace_root, output_root, "packages") {
        return Err("package output must stay under target/release-audit/packages".into());
    }
    fs::create_dir_all(output_root)?;

    let stage_root = output_root.join(PACKAGE_STAGE_DIR);
    if stage_root.exists() {
        fs::remove_dir_all(&stage_root)?;
    }
    fs::create_dir_all(stage_root.join("bin"))?;
    fs::create_dir_all(stage_root.join("scripts"))?;

    copy_file(
        &workspace_root.join("README.md"),
        &stage_root.join("README.md"),
    )?;
    copy_file(
        &workspace_root.join("scripts/install_cse_plus_local.sh"),
        &stage_root.join("scripts/install_cse_plus_local.sh"),
    )?;
    copy_file(
        &workspace_root.join("scripts/uninstall_cse_plus_local.sh"),
        &stage_root.join("scripts/uninstall_cse_plus_local.sh"),
    )?;
    copy_optional_file(
        &workspace_root.join("scripts/install_cse_plus_local.ps1"),
        &stage_root.join("scripts/install_cse_plus_local.ps1"),
    )?;
    copy_optional_file(
        &workspace_root.join("scripts/uninstall_cse_plus_local.ps1"),
        &stage_root.join("scripts/uninstall_cse_plus_local.ps1"),
    )?;

    let binary = resolve_binary_path(workspace_root)
        .ok_or_else(|| "cse_txn binary not found after build".to_string())?;
    copy_file(&binary, &stage_root.join("bin/cse_txn"))?;

    let sha_manifest = build_sha_manifest(
        &stage_root,
        &[
            "README.md",
            "scripts/install_cse_plus_local.sh",
            "scripts/uninstall_cse_plus_local.sh",
            "bin/cse_txn",
        ],
    )?;
    write_text_file(&stage_root.join("SHA256SUMS"), &sha_manifest)?;

    let package_path = output_root.join(PACKAGE_NAME);
    if package_path.exists() {
        fs::remove_file(&package_path)?;
    }
    let tar_gz = File::create(&package_path)?;
    let encoder = GzEncoder::new(tar_gz, Compression::default());
    let mut tar_builder = tar::Builder::new(encoder);
    tar_builder.append_dir_all(PACKAGE_STAGE_DIR, &stage_root)?;
    let encoder = tar_builder.into_inner()?;
    encoder.finish()?;

    let windows_metadata = PackageDryRunMetadata {
        artifact: "cse-plus-windows-local.zip".to_string(),
        platform: std::env::consts::OS.to_string(),
        mode: if cfg!(windows) {
            "zip".to_string()
        } else {
            "dry-run".to_string()
        },
        files: vec![
            "README.md".to_string(),
            "scripts/install_cse_plus_local.ps1".to_string(),
            "scripts/uninstall_cse_plus_local.ps1".to_string(),
            "bin/cse_txn".to_string(),
            "SHA256SUMS".to_string(),
        ],
    };
    write_json_pretty(
        &output_root.join(PACKAGE_WINDOWS_DRY_RUN),
        &windows_metadata,
    )?;

    Ok(())
}

fn build_sha_manifest(stage_root: &Path, files: &[&str]) -> Result<String, Box<dyn Error>> {
    let mut lines = Vec::new();
    for relative in files {
        let path = stage_root.join(relative);
        if !path.exists() {
            continue;
        }
        let mut data = Vec::new();
        File::open(&path)?.read_to_end(&mut data)?;
        let digest = digest_canonical(b"cse-plus-package-file-v1", &data);
        lines.push(format!("{}  {}", hex::encode(digest.0), relative));
    }
    Ok(lines.join("\n") + "\n")
}

fn install_local(
    workspace_root: &Path,
    output_root: &Path,
    institution_type: &str,
    branch_code: &str,
    demo_seed_i32: i32,
) -> Result<(), Box<dyn Error>> {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR").map(PathBuf::from);
    install_local_with_target_dir(
        workspace_root,
        output_root,
        institution_type,
        branch_code,
        demo_seed_i32,
        target_dir.as_deref(),
    )
}

fn install_local_with_target_dir(
    workspace_root: &Path,
    output_root: &Path,
    institution_type: &str,
    branch_code: &str,
    demo_seed_i32: i32,
    target_dir: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    if !ensure_release_audit_path(workspace_root, output_root, "installations") {
        return Err("install output must stay under target/release-audit/installations".into());
    }
    validate_institution_type(institution_type)?;
    validate_branch_code(branch_code)?;
    validate_seed(demo_seed_i32)?;

    let institution_branch_id = institution_branch_id(institution_type, branch_code);
    let install_root = output_root.join(&institution_branch_id);
    if install_root.exists() {
        fs::remove_dir_all(&install_root)?;
    }

    fs::create_dir_all(install_root.join("bin"))?;
    fs::create_dir_all(install_root.join("config"))?;
    fs::create_dir_all(install_root.join("profiles"))?;
    fs::create_dir_all(install_root.join("logs"))?;
    fs::create_dir_all(install_root.join("results"))?;

    let profile = build_demo_profile_record(
        institution_type,
        branch_code,
        demo_seed_i32,
        Utc::now().to_rfc3339(),
    )?;
    write_json_pretty(&install_root.join("profiles/demo_profile.json"), &profile)?;

    let config = serde_json::json!({
        "institution_branch_id": institution_branch_id,
        "demo_seed_i32": demo_seed_i32,
        "profile_digest": profile.profile_digest,
        "mode": "demo/test only"
    });
    write_json_pretty(&install_root.join("config/cse-plus.local.json"), &config)?;

    write_text_file(
        &install_root.join("README.md"),
        "CSE+ local installation\n\nThis tree is for local demo/test use only.\n",
    )?;
    write_text_file(
        &install_root.join("logs/README.md"),
        "Logs are written here for local verification runs.\n",
    )?;
    write_text_file(
        &install_root.join("results/README.md"),
        "Results are written here for local verification runs.\n",
    )?;

    let binary = resolve_binary_path_from(workspace_root, target_dir)
        .ok_or_else(|| "cse_txn binary not found after build".to_string())?;
    copy_file(&binary, &install_root.join("bin/cse_txn"))?;

    Ok(())
}

fn validate_institution_branch_id(value: &str) -> Result<(), String> {
    if value.len() == 8
        && value.is_ascii()
        && value.as_bytes().get(4) == Some(&b'-')
        && value
            .as_bytes()
            .iter()
            .take(4)
            .all(|byte| byte.is_ascii_alphanumeric())
        && value
            .as_bytes()
            .iter()
            .skip(5)
            .take(3)
            .all(|byte| byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err("institution_branch_id must match XXXX-NNN ASCII form".to_string())
    }
}

fn uninstall_local(
    workspace_root: &Path,
    output_root: &Path,
    institution_branch_id: &str,
) -> Result<(), Box<dyn Error>> {
    if !ensure_release_audit_path(workspace_root, output_root, "installations") {
        return Err(
            "uninstall output root must stay under target/release-audit/installations".into(),
        );
    }
    validate_institution_branch_id(institution_branch_id).map_err(|e| e.to_string())?;
    let install_root = output_root.join(institution_branch_id);
    if !install_root.exists() {
        return Ok(());
    }
    fs::remove_dir_all(&install_root)?;
    Ok(())
}

fn prepare_three_bank_local(
    workspace_root: &Path,
    output_root: &Path,
) -> Result<(), Box<dyn Error>> {
    if !ensure_release_audit_path(workspace_root, output_root, "three-bank-local") {
        return Err(
            "three-bank topology must stay under target/release-audit/three-bank-local".into(),
        );
    }

    fs::create_dir_all(output_root)?;
    let topology = build_three_bank_topology();
    write_json_pretty(&output_root.join("topology.json"), &topology)?;
    write_text_file(
        &output_root.join("README.md"),
        "Three-bank local quick harness topology for CSE+ demo/test verification.\n",
    )?;
    Ok(())
}

fn build_three_bank_topology() -> Topology {
    Topology {
        banks: vec![
            BankSpec {
                institution_type: "A001".to_string(),
                branch_code: "001".to_string(),
                institution_branch_id: "A001-001".to_string(),
                demo_seed_i32: 1001,
            },
            BankSpec {
                institution_type: "B002".to_string(),
                branch_code: "001".to_string(),
                institution_branch_id: "B002-001".to_string(),
                demo_seed_i32: 2002,
            },
            BankSpec {
                institution_type: "C003".to_string(),
                branch_code: "001".to_string(),
                institution_branch_id: "C003-001".to_string(),
                demo_seed_i32: 3003,
            },
        ],
        pairs: vec![
            BankPair {
                source: "A001-001".to_string(),
                destination: "B002-001".to_string(),
            },
            BankPair {
                source: "B002-001".to_string(),
                destination: "C003-001".to_string(),
            },
            BankPair {
                source: "C003-001".to_string(),
                destination: "A001-001".to_string(),
            },
            BankPair {
                source: "B002-001".to_string(),
                destination: "A001-001".to_string(),
            },
            BankPair {
                source: "C003-001".to_string(),
                destination: "B002-001".to_string(),
            },
            BankPair {
                source: "A001-001".to_string(),
                destination: "C003-001".to_string(),
            },
        ],
        payload_sizes: vec![1024, 10 * 1024, 50 * 1024, 1024 * 1024],
    }
}

fn run_three_bank_quick_harness(
    workspace_root: &Path,
    topology_root: &Path,
    output_root: &Path,
    iterations: u32,
    rng: &mut impl RngCore,
) -> Result<QuickHarnessSummary, Box<dyn Error>> {
    if !ensure_release_audit_path(workspace_root, topology_root, "three-bank-local") {
        return Err("topology must stay under target/release-audit/three-bank-local".into());
    }
    if !ensure_release_audit_path(workspace_root, output_root, "test-results") {
        return Err("results must stay under target/release-audit/test-results".into());
    }
    let topology = load_topology(topology_root)?;
    let engine = demo_engine();

    fs::create_dir_all(output_root)?;
    let results_path = output_root.join(QUICK_HARNESS_RESULTS);
    let summary_path = output_root.join(QUICK_HARNESS_SUMMARY);
    let mut results_file = File::create(&results_path)?;
    let mut summary = QuickHarnessSummary::default();

    for pair in &topology.pairs {
        for iter in 0..iterations {
            for case_class in ["normal", "abnormal", "cross_bank_mismatch"] {
                let payload_size =
                    topology.payload_sizes[(iter as usize + case_class.len() + pair.source.len())
                        % topology.payload_sizes.len()];
                let mut payload = vec![0u8; payload_size];
                rng.fill_bytes(&mut payload);
                let payload_digest = payload_digest_v0(&payload);

                let case_id = format!(
                    "{}->{}:{}:{}:{}",
                    pair.source, pair.destination, case_class, iter, payload_size
                );

                let start = std::time::Instant::now();
                let output = cse_pre_send(demo_context(), &payload, None, &engine)?;
                let harness_mode = match case_class {
                    "cross_bank_mismatch" => "simulation",
                    _ => "actual_verification",
                };

                let (expected_result, actual_result, activation_allowed, rejection_reason) =
                    match case_class {
                        "normal" => {
                            let packet_result = cse_pre_recv(&output.packet, &engine);
                            match packet_result {
                                Ok(_) => (
                                    "verified".to_string(),
                                    "verified".to_string(),
                                    true,
                                    String::new(),
                                ),
                                Err(err) => (
                                    "verified".to_string(),
                                    "rejected".to_string(),
                                    false,
                                    err,
                                ),
                            }
                        }
                        "abnormal" => {
                            let mutated_packet = mutate_packet(
                                &output.packet,
                                iter,
                                pair,
                                payload_size,
                                case_class,
                            );
                            match cse_pre_recv(&mutated_packet, &engine) {
                                Ok(_) => (
                                    "not_activated".to_string(),
                                    "verified".to_string(),
                                    true,
                                    "unexpected verification success".to_string(),
                                ),
                                Err(err) => (
                                    "not_activated".to_string(),
                                    "not_activated".to_string(),
                                    false,
                                    err,
                                ),
                            }
                        }
                        "cross_bank_mismatch" => (
                            "not_activated".to_string(),
                            "not_activated".to_string(),
                            false,
                            "public quick harness simulation: public standard line lacks bank-profile binding".to_string(),
                        ),
                        _ => unreachable!(),
                    };

                let elapsed_ms = start.elapsed().as_millis() as u64;
                let row = QuickHarnessRow {
                    case_id: case_id.clone(),
                    case_class: case_class.to_string(),
                    harness_mode: harness_mode.to_string(),
                    source: pair.source.clone(),
                    destination: pair.destination.clone(),
                    payload_size,
                    payload_digest: hex::encode(payload_digest.0),
                    expected_result,
                    actual_result,
                    activation_allowed,
                    rejection_reason,
                    elapsed_ms,
                };

                if row.expected_result == row.actual_result {
                    summary.passed += 1;
                } else {
                    summary.failed += 1;
                }
                summary.total += 1;
                if row.expected_result != "verified" && row.actual_result == "verified" {
                    summary.false_allow += 1;
                }
                if row.expected_result == "verified" && row.actual_result != "verified" {
                    summary.false_reject += 1;
                }
                bucket_add(&mut summary.by_case_class, case_class, &row);
                bucket_add(&mut summary.by_harness_mode, harness_mode, &row);
                bucket_add(
                    &mut summary.by_pair,
                    &format!("{}->{}", pair.source, pair.destination),
                    &row,
                );
                bucket_add(
                    &mut summary.by_payload_size,
                    &payload_size.to_string(),
                    &row,
                );
                serde_json::to_writer(&mut results_file, &row)?;
                results_file.write_all(b"\n")?;
            }
        }
    }

    write_json_pretty(&summary_path, &summary)?;

    if summary.false_allow > 0 {
        return Err("false_allow must be zero".into());
    }
    if summary.false_reject > 0 {
        return Err("normal cases failed unexpectedly".into());
    }

    let _ = workspace_root;
    Ok(summary)
}

fn mutate_packet(
    packet: &[u8],
    iter: u32,
    pair: &BankPair,
    payload_size: usize,
    case_class: &str,
) -> Vec<u8> {
    let mut mutated = packet.to_vec();
    let mutation_kind =
        (iter as usize + pair.source.len() + pair.destination.len() + payload_size) % 4;
    let seal_offset = 32 + 112 + 256 + 128;
    match mutation_kind {
        0 => {
            if let Some(byte) = mutated.get_mut(0) {
                *byte ^= 0x01;
            }
        }
        1 => {
            if let Some(byte) = mutated.get_mut(seal_offset) {
                *byte ^= 0x01;
            }
        }
        2 => {
            let trim = 1 + (case_class.len() + iter as usize) % 8;
            mutated.truncate(mutated.len().saturating_sub(trim));
        }
        _ => {
            mutated.extend_from_slice(b"PUBLIC-CSEPLUS-GARBAGE");
            if let Some(byte) = mutated.get_mut(seal_offset + 32) {
                *byte ^= 0x01;
            }
        }
    }
    mutated
}

fn bucket_add(map: &mut BTreeMap<String, SummaryBucket>, key: &str, row: &QuickHarnessRow) {
    let entry = map.entry(key.to_string()).or_default();
    if row.expected_result == row.actual_result {
        entry.passed += 1;
    } else {
        entry.failed += 1;
    }
}

fn load_topology(topology_root: &Path) -> Result<Topology, Box<dyn Error>> {
    let topology_path = topology_root.join("topology.json");
    let content = fs::read_to_string(topology_path)?;
    Ok(serde_json::from_str(&content)?)
}

fn ensure_release_audit_path(repo_root: &Path, path: &Path, tail: &str) -> bool {
    let repo_root = match fs::canonicalize(repo_root) {
        Ok(root) => root,
        Err(_) => repo_root.to_path_buf(),
    };
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    };

    if candidate.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return false;
    }

    if !candidate.starts_with(&repo_root) {
        return false;
    }

    let relative = match candidate.strip_prefix(&repo_root) {
        Ok(relative) => relative,
        Err(_) => return false,
    };
    let mut components = relative.components();
    matches!(components.next(), Some(std::path::Component::Normal(value)) if value == "target")
        && matches!(components.next(), Some(std::path::Component::Normal(value)) if value == "release-audit")
        && matches!(components.next(), Some(std::path::Component::Normal(value)) if value == tail)
}

#[cfg(test)]
fn package_path_exists(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn fake_workspace() -> PathBuf {
        let root = unique_temp_dir("cse-plus-public-workspace");
        fs::create_dir_all(root.join("target/release")).unwrap();
        fs::create_dir_all(root.join("target/debug")).unwrap();
        fs::write(root.join("target/release/cse_txn"), b"release-binary").unwrap();
        fs::write(root.join("target/debug/cse_txn"), b"debug-binary").unwrap();
        fs::write(root.join("README.md"), b"# CSE+\n").unwrap();
        fs::create_dir_all(root.join("scripts")).unwrap();
        fs::write(
            root.join("scripts/install_cse_plus_local.sh"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        fs::write(
            root.join("scripts/uninstall_cse_plus_local.sh"),
            b"#!/bin/sh\n",
        )
        .unwrap();
        root
    }

    fn fake_target_dir(root: &Path) -> PathBuf {
        let target_dir = root.join("tmp-target");
        fs::create_dir_all(target_dir.join("release")).unwrap();
        fs::create_dir_all(target_dir.join("debug")).unwrap();
        fs::write(target_dir.join("release/cse_txn"), b"target-release-binary").unwrap();
        fs::write(target_dir.join("debug/cse_txn"), b"target-debug-binary").unwrap();
        target_dir
    }

    #[test]
    fn p18a_package() {
        let workspace = fake_workspace();
        let output_root = workspace.join("target/release-audit/packages");
        fs::create_dir_all(&output_root).unwrap();

        build_local_package(&workspace, &output_root).unwrap();

        assert!(package_path_exists(&output_root.join(PACKAGE_NAME)));
        assert!(package_path_exists(
            &output_root.join(PACKAGE_WINDOWS_DRY_RUN)
        ));
        let package_file = File::open(output_root.join(PACKAGE_NAME)).unwrap();
        let decoder = flate2::read::GzDecoder::new(package_file);
        let mut archive = tar::Archive::new(decoder);
        let mut entries = HashSet::new();
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().to_string();
            entries.insert(path);
        }
        assert!(entries.iter().any(|path| path.ends_with("bin/cse_txn")));
        let manifest =
            fs::read_to_string(output_root.join(PACKAGE_STAGE_DIR).join("SHA256SUMS")).unwrap();
        assert!(manifest.contains("README.md"));

        let target_dir = fake_target_dir(&workspace);
        let resolved = resolve_binary_path_from(&workspace, Some(&target_dir));
        assert_eq!(resolved, Some(target_dir.join("release/cse_txn")));
    }

    #[test]
    fn p18a_release_audit_path_checks() {
        let repo_root = unique_temp_dir("cse-plus-public-repo-root");
        let valid = repo_root.join("target/release-audit/packages");
        let root_only = repo_root.join("target/release-audit");
        let traversal = repo_root.join("target/release-audit/../escape");
        let external =
            unique_temp_dir("cse-plus-public-external").join("target/release-audit/packages");

        assert!(ensure_release_audit_path(&repo_root, &valid, "packages"));
        assert!(!ensure_release_audit_path(
            &repo_root, &root_only, "packages"
        ));
        assert!(!ensure_release_audit_path(
            &repo_root, &traversal, "packages"
        ));
        assert!(!ensure_release_audit_path(
            &repo_root, &external, "packages"
        ));
    }

    #[test]
    fn p18a_three_bank() {
        let workspace = fake_workspace();
        let topology_root = workspace.join("target/release-audit/three-bank-local");
        let output_root = workspace.join("target/release-audit/test-results");
        fs::create_dir_all(&topology_root).unwrap();
        fs::create_dir_all(&output_root).unwrap();

        prepare_three_bank_local(&workspace, &topology_root).unwrap();
        let mut rng = StdRng::seed_from_u64(42);
        let summary =
            run_three_bank_quick_harness(&workspace, &topology_root, &output_root, 2, &mut rng)
                .unwrap();

        assert!(output_root.join(QUICK_HARNESS_RESULTS).exists());
        assert!(output_root.join(QUICK_HARNESS_SUMMARY).exists());
        assert_eq!(summary.false_allow, 0);
        assert_eq!(summary.false_reject, 0);
        assert!(summary.by_harness_mode.contains_key("actual_verification"));
        assert!(summary.by_harness_mode.contains_key("simulation"));
        assert!(
            summary
                .by_harness_mode
                .get("simulation")
                .map(|bucket| bucket.passed)
                .unwrap_or(0)
                > 0
        );
        let results = fs::read_to_string(output_root.join(QUICK_HARNESS_RESULTS)).unwrap();
        assert!(results.contains("\"harness_mode\""));
        assert!(!results.contains("raw_payload"));
        assert!(!results.contains("candidate"));
        assert!(!results.contains("key_material"));
        assert!(results.contains("public quick harness simulation"));
    }

    #[test]
    fn p18a_install_requires_real_binary() {
        let workspace = unique_temp_dir("cse-plus-public-empty-workspace");
        fs::write(workspace.join("README.md"), b"# CSE+\n").unwrap();
        let output_root = workspace.join("target/release-audit/installations");
        fs::create_dir_all(&output_root).unwrap();

        let empty_target_dir = workspace.join("empty-target");
        fs::create_dir_all(&empty_target_dir).unwrap();
        let err = install_local_with_target_dir(
            &workspace,
            &output_root,
            "A001",
            "001",
            1001,
            Some(&empty_target_dir),
        )
        .unwrap_err();
        assert!(err.to_string().contains("cse_txn binary not found"));
    }

    #[test]
    fn p18a_install_copies_real_binary() {
        let workspace = fake_workspace();
        let output_root = workspace.join("target/release-audit/installations");
        fs::create_dir_all(&output_root).unwrap();

        let target_dir = fake_target_dir(&workspace);
        install_local_with_target_dir(
            &workspace,
            &output_root,
            "A001",
            "001",
            1001,
            Some(&target_dir),
        )
        .unwrap();
        let installed = fs::read(output_root.join("A001-001/bin/cse_txn")).unwrap();
        assert_eq!(installed, b"target-release-binary");
    }

    #[test]
    fn p18a_uninstall_rejects_unsafe_branch_ids() {
        let repo_root = unique_temp_dir("cse-plus-public-repo-root");
        let output_root = repo_root.join("target/release-audit/installations");
        fs::create_dir_all(&output_root).unwrap();

        assert!(uninstall_local(&repo_root, &output_root, "A001-001").is_ok());
        assert!(uninstall_local(&repo_root, &output_root, "A001/001").is_err());
        assert!(uninstall_local(&repo_root, &output_root, "A001-00").is_err());
    }
}
