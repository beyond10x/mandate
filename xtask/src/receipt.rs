//! The coverage receipt: what the manifest was written against, as digests and counts.
//!
//! A manifest is a statement about a contract, a set of sources and an emission, and the
//! three move independently. The receipt binds them: four digests and the per-kind counts,
//! written by `cargo xtask generate` beside every other generated file, so
//! `cargo xtask contracts` byte-compares it against a fresh one like every other projection.
//! A manifest edited without regenerating, or an ESS source changed without the manifest
//! following, is then a failing gate rather than a claim nobody re-derived.
//!
//! # What it binds, and what it deliberately does not
//!
//! Digests and counts only (the wave D ruling): the ESS toolchain's own version, the ESS
//! sources, the compiled model, the emitted contract crate and the manifest — plus the table.
//! **No test ids.** Proving a test id is a live check that needs every test binary built, and
//! nesting a `cargo test --no-run` inside `generate()` would make emitting a projection
//! depend on compiling the workspace. That check belongs to [`crate::coverage`], which runs
//! it when the gate asks, and it is why a receipt stays cheap enough to write on every
//! generation.
//!
//! # Byte-stability
//!
//! Every input is read from `root` and every map is ordered — `serde_json`'s object is a
//! `BTreeMap` here, and the tree digests walk sorted paths — so two runs over one tree write
//! the same bytes. That is not a nicety: the receipt is compared byte for byte, so a
//! nondeterministic field would report drift the contract does not have.
use crate::emit;
use serde_json::{Map, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The receipt format this writer produces.
pub const FORMAT: &str = "mandate-coverage-receipt/1";

/// Write `<out>/coverage/receipt.json` from the inputs under `<source>`.
///
/// Two roots, the way `generate()`'s other writers are shaped: the repository the manifest
/// and the specification are read from, and the output root the projections are written to,
/// which is `generated/` for the tree and a scratch directory for `contracts()`' byte-compare.
///
/// # Errors
///
/// When an input is unreadable, when the manifest is not the format [`crate::coverage`]
/// reads, or when the ESS toolchain cannot state its version.
pub fn receipt(source: &Path, out: &Path) -> Result<()> {
    let root = source;
    let manifest_path = root.join("contracts/coverage.json");
    let manifest_bytes =
        fs::read(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    if manifest["format"] != crate::coverage::FORMAT {
        return Err(format!(
            "{}: {} is not the coverage manifest format {}",
            manifest_path.display(),
            manifest["format"],
            crate::coverage::FORMAT
        )
        .into());
    }

    let model_path = root.join("generated/ir/system.json");
    let model = fs::read(&model_path).map_err(|e| format!("{}: {e}", model_path.display()))?;

    let mut receipt = Map::new();
    receipt.insert("format".to_owned(), Value::from(FORMAT));
    receipt.insert("ess_version".to_owned(), Value::from(ess_version()?));
    receipt.insert(
        "source_digest".to_owned(),
        Value::from(tree_digest(&root.join("systems/mandate"))?),
    );
    receipt.insert("ir_digest".to_owned(), Value::from(emit::digest(&model)));
    receipt.insert(
        "contract_crate_digest".to_owned(),
        Value::from(tree_digest(
            &root.join("generated/rust/mandate-contract/src"),
        )?),
    );
    receipt.insert(
        "manifest_digest".to_owned(),
        Value::from(emit::digest(&manifest_bytes)),
    );
    receipt.insert("counts".to_owned(), counts(&manifest)?);

    let directory = out.join("coverage");
    fs::create_dir_all(&directory).map_err(|e| format!("{}: {e}", directory.display()))?;
    let written = format!(
        "{}\n",
        serde_json::to_string_pretty(&Value::Object(receipt))?
    );
    fs::write(directory.join("receipt.json"), written)?;
    Ok(())
}

/// The toolchain that compiled the model, as it names itself.
///
/// Read from the tool rather than written here: a repin that changes the projections without
/// changing a source would otherwise leave every digest equal and the receipt silent about
/// the one thing that moved.
fn ess_version() -> Result<String> {
    let out = Command::new("ess")
        .arg("--version")
        .output()
        .map_err(|e| format!("ess --version: {e}"))?;
    if !out.status.success() {
        return Err(format!("ess --version: {}", out.status).into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// One digest over a whole directory.
///
/// Each file contributes its path, a separator no path can contain, its length and its bytes,
/// in sorted path order. The length is what stops two trees that differ only in where one
/// file ends and the next begins from reaching the same digest.
fn tree_digest(directory: &Path) -> Result<String> {
    let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    walk(directory, directory, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut canonical: Vec<u8> = Vec::new();
    for (path, bytes) in &files {
        canonical.extend_from_slice(path.to_string_lossy().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes.len().to_string().as_bytes());
        canonical.push(0);
        canonical.extend_from_slice(bytes);
    }
    Ok(emit::digest(&canonical))
}

fn walk(base: &Path, directory: &Path, into: &mut Vec<(PathBuf, Vec<u8>)>) -> Result<()> {
    for entry in fs::read_dir(directory).map_err(|e| format!("{}: {e}", directory.display()))? {
        let path = entry
            .map_err(|e| format!("{}: {e}", directory.display()))?
            .path();
        if path.is_dir() {
            walk(base, &path, into)?;
        } else {
            let relative = path.strip_prefix(base)?.to_owned();
            into.push((relative, fs::read(&path)?));
        }
    }
    Ok(())
}

/// The manifest's own table: how many elements of each kind carry each status.
fn counts(manifest: &Value) -> Result<Value> {
    let entries = manifest["entries"]
        .as_array()
        .ok_or("the manifest states no entries")?;
    let mut table: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for entry in entries {
        let kind = entry["kind"].as_str().ok_or("an entry states no kind")?;
        let status = entry["status"]
            .as_str()
            .ok_or("an entry states no status")?;
        *table
            .entry(kind.to_owned())
            .or_default()
            .entry(status.to_owned())
            .or_default() += 1;
    }
    let mut out = Map::new();
    for (kind, statuses) in table {
        let mut row = Map::new();
        for (status, count) in statuses {
            row.insert(status, Value::from(count));
        }
        out.insert(kind, Value::Object(row));
    }
    Ok(Value::Object(out))
}
