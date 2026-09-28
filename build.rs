//! Engine content-pin guard (GH#503, CR-ENGINE-PIN-001).
//!
//! The risk engine is consumed as `percolator = { path = "../percolator" }` so the two
//! repos can be edited in lockstep. A path dependency is not content-addressed: Cargo.lock
//! records no source and no checksum for it, so without this script every direct
//! `cargo build` / `cargo build-sbf` / `cargo test` silently compiles whatever bytes are at
//! `../percolator` at that moment. `scripts/ci-test.sh` checks the sibling HEAD, but only
//! builds that go through that script were protected.
//!
//! This moves the check into the build itself, so it holds for every consumer of this
//! crate. It FAILS CLOSED unless the sibling engine:
//!   (a) is a git checkout whose HEAD equals `ENGINE_CI_SIBLING` from the committed
//!       `ci/deployed-refs.env` (the same pin ci.yml checks out and ci-test.sh asserts), and
//!   (b) has no uncommitted or untracked changes in the files that make up the library
//!       build (`src/`, `Cargo.toml`, `build.rs`) -- a dirty tree can carry the right HEAD
//!       and different bytes.
//!
//! Local experiments against another engine (an engine fix branch, a bisect) are expected;
//! set `PERCOLATOR_ENGINE_UNPINNED=1` for those. The build then proceeds and prints a
//! warning naming the engine commit it actually used, and the artifact is a local
//! experiment -- never a deploy candidate. Moving the pin is a reviewable one-line change
//! to `ci/deployed-refs.env`.
//!
//! This script only reads; it emits no cfg/env into the crate, so it cannot change program
//! behaviour. Note that merely having a build script changes the crate's metadata hash, so
//! the SBF artifact is not byte-identical to a build of the same source without this file
//! (measured: same length, ~1.6 KB of hash-ordered bytes differ). Compare artifacts only
//! between builds of the same commit.

use std::path::{Path, PathBuf};
use std::process::Command;

const ENGINE_REL: &str = "../percolator";
const REFS_REL: &str = "ci/deployed-refs.env";
const PIN_KEY: &str = "ENGINE_CI_SIBLING";
const BYPASS_ENV: &str = "PERCOLATOR_ENGINE_UNPINNED";
/// Paths inside the engine whose contents feed the library build of the dependency.
const ENGINE_BUILD_PATHS: &[&str] = &["src", "Cargo.toml", "build.rs"];

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let engine = manifest_dir.join(ENGINE_REL);
    let refs = manifest_dir.join(REFS_REL);

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", refs.display());
    println!("cargo:rerun-if-env-changed={BYPASS_ENV}");
    for p in ENGINE_BUILD_PATHS {
        let p = engine.join(p);
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
    watch_engine_git_head(&engine);

    let bypass = std::env::var(BYPASS_ENV).map(|v| v == "1").unwrap_or(false);

    match verify(&engine, &refs) {
        Ok(head) => {
            // Visible only with -vv; the success path stays quiet.
            eprintln!("percolator-prog: engine sibling verified at {head} ({PIN_KEY})");
        }
        Err(msg) if bypass => {
            println!(
                "cargo:warning=ENGINE NOT PINNED ({BYPASS_ENV}=1): {msg}. \
                 This build is a local experiment, NOT a deploy candidate."
            );
        }
        Err(msg) => {
            eprintln!();
            eprintln!("error: percolator engine sibling does not match the committed pin (GH#503)");
            eprintln!("  {msg}");
            eprintln!();
            eprintln!(
                "  The engine is a path dependency ({ENGINE_REL}); Cargo cannot content-pin it,"
            );
            eprintln!("  so this build script does. Fix one of:");
            eprintln!("    git -C {ENGINE_REL} checkout <{PIN_KEY} from {REFS_REL}>   (and commit/stash local edits)");
            eprintln!("    move the pin in {REFS_REL} (a reviewable change), or");
            eprintln!(
                "    {BYPASS_ENV}=1 for a deliberate local experiment (never a deploy artifact)."
            );
            std::process::exit(1);
        }
    }
}

fn verify(engine: &Path, refs: &Path) -> Result<String, String> {
    let pin = read_pin(refs)?;
    if !engine.join("Cargo.toml").exists() {
        return Err(format!("{} does not exist", engine.display()));
    }
    let head = git(engine, &["rev-parse", "HEAD"]).map_err(|e| {
        format!(
            "{} is not an identifiable git checkout ({e})",
            engine.display()
        )
    })?;
    if head != pin {
        return Err(format!(
            "{PIN_KEY} is {pin} but {ENGINE_REL} HEAD is {head}"
        ));
    }
    let mut args = vec!["status", "--porcelain", "--untracked-files=all", "--"];
    args.extend_from_slice(ENGINE_BUILD_PATHS);
    let dirty =
        git(engine, &args).map_err(|e| format!("git status failed in {ENGINE_REL}: {e}"))?;
    if !dirty.is_empty() {
        let first: Vec<&str> = dirty.lines().take(5).collect();
        return Err(format!(
            "{ENGINE_REL} is at the pinned HEAD {head} but has local changes: {}",
            first.join(", ")
        ));
    }
    Ok(head)
}

fn read_pin(refs: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(refs)
        .map_err(|e| format!("cannot read {}: {e}", refs.display()))?;
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix(PIN_KEY).and_then(|r| r.strip_prefix('=')) {
            if found.is_some() {
                return Err(format!(
                    "{PIN_KEY} is assigned more than once in {REFS_REL}"
                ));
            }
            found = Some(v.trim().trim_matches('"').to_string());
        }
    }
    let pin = found.ok_or_else(|| format!("{PIN_KEY} is not set in {REFS_REL}"))?;
    if pin.len() != 40 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "{PIN_KEY} in {REFS_REL} must be a full 40-hex commit id, got '{pin}'"
        ));
    }
    Ok(pin.to_ascii_lowercase())
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run git: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Re-run this script when the engine's HEAD moves (checkout, commit, reset), including
/// when the sibling is a linked worktree whose refs live in the common git dir.
fn watch_engine_git_head(engine: &Path) {
    let Ok(git_dir) = git(engine, &["rev-parse", "--absolute-git-dir"]) else {
        return;
    };
    let git_dir = PathBuf::from(git_dir);
    let head = git_dir.join("HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());
    }
    let Ok(common) = git(engine, &["rev-parse", "--git-common-dir"]) else {
        return;
    };
    let common = if Path::new(&common).is_absolute() {
        PathBuf::from(common)
    } else {
        engine.join(common)
    };
    let packed = common.join("packed-refs");
    if packed.exists() {
        println!("cargo:rerun-if-changed={}", packed.display());
    }
    if let Ok(sym) = git(engine, &["symbolic-ref", "-q", "HEAD"]) {
        let r = common.join(sym);
        if r.exists() {
            println!("cargo:rerun-if-changed={}", r.display());
        }
    }
}
