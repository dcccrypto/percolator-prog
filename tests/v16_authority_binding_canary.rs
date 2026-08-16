//! Structural canary for the per-asset authority model.
//!
//! `handle_update_asset_authority` lets an asset's `asset_admin` rotate any of that
//! asset's authorities **without the current holder's signature** — `admin_signed`
//! short-circuits `expect_live_authority(&current_value, ...)`. That is safe exactly as
//! long as every authority holder is a signable keypair: a keypair holder is a
//! counterparty that can inspect `asset_admin` before committing capital, require it be
//! burned to zero (which makes current-holder consent mandatory on every rotation), or
//! walk away.
//!
//! `handle_create_lp_vault` binds a program-derived address —
//! `backing_bucket_authority = registry_pda` — as an asset authority. A PDA cannot
//! inspect, cannot require, and cannot refuse, and nothing in this program CPIs back in
//! to sign as it. That made the binding seizable and every LP depositor's principal
//! withdrawable by the asset's admin (#414); #415 guards that one derivation by name.
//!
//! A *second* PDA bound to any authority field re-opens the same door silently. There is
//! no runtime behaviour to assert against, because the exposure is created by the
//! binding itself rather than by any reachable state — so this test freezes the set of
//! expressions ever assigned to an authority field. Introducing a binding fails here,
//! with a pointer to the guard that must be extended to cover it.
//!
//! This complements #415's behavioural tests rather than replacing them: it catches the
//! case those cannot, a future feature introducing a new non-signing authority holder.

/// Fields whose value decides who may act as an authority for an asset or the market.
const AUTHORITY_FIELDS: [&str; 6] = [
    "asset_admin",
    "insurance_authority",
    "insurance_operator",
    "backing_bucket_authority",
    "oracle_authority",
    "marketauth",
];

/// Every right-hand side currently assigned to an authority field.
///
/// Safe shapes are: a caller-supplied pubkey (the caller names its own counterparty, and
/// a non-zero incoming key must co-sign), the signing key itself, a carry-forward of an
/// already-validated profile, or a burn to zero. All are signable keypairs, or a copy of
/// one, so the holder can always consent — or refuse — for itself.
/// Entries are pruned when they stop matching: a stale allowlist is how the next
/// reviewer stops trusting this file. `asset_admin` and `cfg.<field>` were listed but
/// matched nothing in the shipped source (verified by removing them and re-running),
/// so they are gone. Re-add one only alongside the assignment that needs it.
const ALLOWED_RIGHT_HAND_SIDES: [&str; 8] = [
    // Caller-supplied instruction parameters, named at activation or rotation.
    "insurance_authority",
    "insurance_operator",
    "backing_bucket_authority",
    "oracle_authority",
    "new_pubkey",
    // The signing activator becomes the asset's cold-storage admin.
    "authority.key.to_bytes()",
    // Carry-forward of an authority already validated on an earlier write.
    "existing.<field>",
    "existing_profile.<field>",
];

/// PDA bindings that are known, reviewed, and individually guarded.
///
/// A binding may only appear here once rotating *away* from it is rejected, because a
/// PDA holder can never sign to defend itself.
///
/// The third element is a source fragment that must be present in the shipped program
/// for the guard to actually exist. Without it this table is an unchecked claim: the
/// binding would be certified "guarded" purely because it is listed here, which is how
/// a canary starts lying. See `guarded_pda_bindings_are_still_present`.
const GUARDED_PDA_BINDINGS: [(&str, &str, &str); 1] = [(
    "backing_bucket_authority = registry_pda.to_bytes()",
    "#415: handle_update_asset_authority rejects rotating ASSET_AUTH_BACKING_BUCKET away \
     from an initialised LP vault registry",
    // Must be a fragment of the GUARD ITSELF, not of anything it merely mentions.
    // `ASSET_AUTH_BACKING_BUCKET` alone is the authority-kind constant and is already
    // present at the deployed commit (it is one of the rotation match arms), so it
    // would report the guard as present when it is not. This branch condition appears
    // 0 times at 19d5d932 and 1 time on #415.
    "kind == ASSET_AUTH_BACKING_BUCKET",
)];

/// Assignment shapes this scanner deliberately does NOT cover.
///
/// - Struct-literal initialisation (`SomeProfile { oracle_authority: value, .. }`). Not
///   scanned because `field: value` is syntactically identical to a struct *definition*
///   and to type annotations, so matching it produces false positives across the file.
///   New authority fields are set by assignment in the handlers today; a future
///   struct-literal initialiser would be invisible here.
/// - `AUTHORITY_FIELDS` is a hardcoded list with nothing tying it to the profile struct,
///   so a newly added authority field is unwatched from the day it is introduced until
///   someone remembers to add it here.
///
/// Whole-buffer overwrite via `copy_from_slice` WAS a gap and is now scanned.
const _DOCUMENTED_SCANNER_GAPS: () = ();

/// Normalises a right-hand side so equivalent forms compare equal: trailing statement
/// punctuation is dropped, and a `<recv>.<field>` carry-forward is collapsed to
/// `<recv>.<field>`, since the source field always matches the assignment target.
fn normalise_rhs(rhs: &str, field: &str) -> String {
    // Only statement punctuation — never `)`, which would corrupt `to_bytes()`.
    let rhs = rhs.trim().trim_end_matches([',', ';']).trim();
    match rhs.strip_suffix(field) {
        Some(prefix) if prefix.ends_with('.') => format!("{prefix}<field>"),
        _ => rhs.to_string(),
    }
}

/// Collects `(field, normalised_rhs, line_number)` for every authority assignment in
/// shipped code.
///
/// Comments are skipped so prose about these fields is not mistaken for code, and
/// `#[cfg(test)]` blocks are skipped because a host-test fixture assigning a literal
/// pubkey never reaches a deployed binary. Brace depth is counted on code lines only, so
/// braces inside comments cannot desynchronise the block tracking.
fn authority_assignments(src: &str) -> Vec<(&'static str, String, usize)> {
    let mut found = Vec::new();
    let mut depth: i32 = 0;
    let mut cfg_test_at: Option<i32> = None;
    let mut cfg_test_pending = false;

    for (idx, line) in src.lines().enumerate() {
        let code = line.trim_start();
        if code.starts_with("//") || code.starts_with('*') {
            continue;
        }

        if code.starts_with("#[cfg(test)]") {
            cfg_test_pending = true;
        }
        let opens = code.matches('{').count() as i32;
        let closes = code.matches('}').count() as i32;
        // The block opened directly under a `#[cfg(test)]` attribute, and everything
        // nested inside it, is test-only.
        if cfg_test_pending && opens > 0 {
            cfg_test_at = Some(depth);
            cfg_test_pending = false;
        } else if cfg_test_pending && !code.starts_with("#[") && code.contains(';') {
            // The attribute applied to a NON-block item that ends at its semicolon
            // (`#[cfg(test)] extern crate std;` at src/v16_program.rs:10). Without
            // this, `cfg_test_pending` stayed armed until the next braced construct
            // and silently swallowed the following real code — the `use percolator::{..}`
            // block — treating shipped lines as test-only.
            cfg_test_pending = false;
        }
        let in_cfg_test = cfg_test_at.is_some();
        depth += opens - closes;
        if let Some(open_depth) = cfg_test_at {
            if depth <= open_depth {
                cfg_test_at = None;
            }
        }
        if in_cfg_test {
            continue;
        }

        for field in AUTHORITY_FIELDS {
            // Whole-buffer overwrite: `profile.<field>.copy_from_slice(&value)` assigns
            // the field just as `=` does, but is invisible to an `=`-only scan.
            let copy_needle = format!("{field}.copy_from_slice(");
            if let Some(at) = code.find(&copy_needle) {
                if !matches!(code[..at].chars().next_back(), Some(c) if c.is_alphanumeric() || c == '_')
                {
                    let arg = code[at + copy_needle.len()..]
                        .rsplit_once(')')
                        .map(|(inner, _)| inner)
                        .unwrap_or("")
                        .trim()
                        .trim_start_matches('&');
                    found.push((field, normalise_rhs(arg, field), idx + 1));
                    continue;
                }
            }

            // A write (`= value`), never a comparison (`== value`) or a struct-literal
            // field (`field: value`).
            //
            // The needle deliberately has NO trailing space. With `"{field} = "` a
            // rustfmt-wrapped assignment —
            //     profile.oracle_authority =
            //         some_pda.to_bytes();
            // — never matched at all (rustfmt strips the trailing whitespace), so the
            // continuation assert below was unreachable: the scanner skipped the line
            // silently. That is exactly the shape a long PDA derivation takes, i.e. the
            // shape this canary exists to catch.
            let needle = format!("{field} =");
            let Some(at) = code.find(&needle) else {
                continue;
            };
            // Reject a longer identifier that merely ends in the same suffix.
            if matches!(code[..at].chars().next_back(), Some(c) if c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            let after = &code[at + needle.len()..];
            // `==` is a comparison, not a write. `=>` is a match arm.
            if after.starts_with('=') || after.starts_with('>') {
                continue;
            }
            let rhs = normalise_rhs(after, field);
            // A continuation line carries its value on the next line; the scanner is
            // line-based, so surface it rather than silently treating it as unknown.
            assert!(
                !rhs.is_empty(),
                "src/v16_program.rs:{}: `{field} =` continues on the next line; the \
                 line-based scanner cannot read it. Fold the assignment onto one line or \
                 teach the scanner to join continuations.",
                idx + 1
            );
            found.push((field, rhs, idx + 1));
        }
    }
    found
}

/// The scanner is the thing that has to be trusted, so exercise it directly on
/// synthetic sources rather than only on the real file — where a shape it fails to
/// see is indistinguishable from a shape that is not there.
#[test]
fn scanner_sees_the_shapes_it_claims_to() {
    // A `#[cfg(test)]` on a NON-block item ends at its semicolon. It must not arm the
    // skip and swallow the real code that follows — the exact leak that made
    // `#[cfg(test)] extern crate std;` (src/v16_program.rs:10) hide the next braced
    // construct.
    let leaky = "\
#[cfg(test)]
extern crate std;

fn handler() {
    profile.oracle_authority = some_pda.to_bytes();
}
";
    let found = authority_assignments(leaky);
    assert_eq!(
        found.len(),
        1,
        "an assignment after `#[cfg(test)] extern crate std;` was skipped: {found:?}"
    );
    assert_eq!(found[0].0, "oracle_authority");

    // A real `#[cfg(test)] mod tests { .. }` block IS skipped.
    let test_mod = "\
#[cfg(test)]
mod tests {
    fn f() {
        profile.oracle_authority = fixture.to_bytes();
    }
}
";
    assert!(
        authority_assignments(test_mod).is_empty(),
        "assignments inside a #[cfg(test)] block must be ignored"
    );

    // Whole-buffer overwrite is an assignment.
    let copied = "fn f() { profile.oracle_authority.copy_from_slice(&some_pda.to_bytes()); }\n";
    let found = authority_assignments(copied);
    assert_eq!(found.len(), 1, "copy_from_slice overwrite not seen: {found:?}");
    assert_eq!(found[0].1, "some_pda.to_bytes()");

    // Comparisons and match arms are not writes.
    let not_writes = "\
fn f() {
    if profile.oracle_authority == other { }
    match k { ASSET_AUTH_ORACLE => profile.asset_admin = new_pubkey, }
}
";
    let found = authority_assignments(not_writes);
    assert_eq!(
        found.len(),
        1,
        "expected only the match-arm write, got: {found:?}"
    );
    assert_eq!(found[0].0, "asset_admin");
}

#[test]
#[should_panic(expected = "continues on the next line")]
fn scanner_surfaces_a_rustfmt_wrapped_assignment() {
    // rustfmt strips trailing whitespace, so the wrapped form ends the line at `=`.
    // The original needle `"{field} = "` (trailing space) never matched it, which made
    // the continuation assert unreachable and let this shape through silently — and a
    // long PDA derivation is exactly what wraps.
    let wrapped = "\
fn f() {
    profile.oracle_authority =
        some_pda.to_bytes();
}
";
    let _ = authority_assignments(wrapped);
}

#[test]
fn no_unreviewed_authority_binding_is_introduced() {
    let src = include_str!("../src/v16_program.rs");
    let assignments = authority_assignments(src);

    assert!(
        !assignments.is_empty(),
        "the scanner matched nothing — the assignment syntax changed and this canary is \
         now blind. Fix the scanner before trusting a green run."
    );

    // Keyed on the (field, value) PAIR, never the value alone: #415's guard is scoped to
    // `kind == ASSET_AUTH_BACKING_BUCKET`, so the very same registry PDA bound to a
    // *different* authority field would be unguarded and seizable. Matching on the value
    // alone would wave that through.
    let guarded: Vec<(&str, String)> = GUARDED_PDA_BINDINGS
        .iter()
        .map(|(binding, _, _)| {
            let (field, rhs) = binding.split_once(" = ").expect("binding is `field = rhs`");
            (field, normalise_rhs(rhs, field))
        })
        .collect();

    let unreviewed: Vec<String> = assignments
        .iter()
        .filter(|(field, rhs, _)| {
            !ALLOWED_RIGHT_HAND_SIDES.contains(&rhs.as_str())
                && !guarded.iter().any(|(gf, grhs)| gf == field && grhs == rhs)
        })
        .map(|(field, rhs, line)| format!("  src/v16_program.rs:{line}: {field} = {rhs}"))
        .collect();

    assert!(
        unreviewed.is_empty(),
        "new authority binding(s) introduced:\n{}\n\n\
         An authority holder that cannot sign cannot consent, and \
         `handle_update_asset_authority` skips the current-holder check whenever \
         `asset_admin` signs. A program-derived holder can therefore be seized, and \
         whatever it custodies drained — that is #414.\n\n\
         If the new value is a keypair the caller supplies or controls, add it to \
         ALLOWED_RIGHT_HAND_SIDES. If it is a PDA, first extend the #415 guard in \
         `handle_update_asset_authority` to reject rotating away from it, then record it \
         in GUARDED_PDA_BINDINGS naming that guard.",
        unreviewed.join("\n")
    );
}

#[test]
fn guarded_pda_bindings_are_still_present() {
    let src = include_str!("../src/v16_program.rs");

    for (binding, guard, _) in GUARDED_PDA_BINDINGS {
        assert!(
            src.contains(binding),
            "`{binding}` is no longer in the source, but it is still registered as a \
             guarded PDA binding covered by {guard}.\n\n\
             If the binding was deliberately removed, drop it from GUARDED_PDA_BINDINGS. \
             If it was renamed or reshaped, this canary has stopped watching it and the \
             entry must be updated to match."
        );
    }
}

/// A `GUARDED_PDA_BINDINGS` entry asserts that rotating away from a PDA binding is
/// rejected. That claim must be checked against the source, not taken on trust.
///
/// Without this, listing a binding here is enough to make it "reviewed": the canary
/// would stay green while certifying the live #414 exposure as guarded by a #415 fix
/// that had not landed yet.
///
/// NOTE ON MERGE ORDER: this fails until #415 is merged, because
/// `handle_update_asset_authority` at the deployed commit (19d5d932) has no
/// `ASSET_AUTH_BACKING_BUCKET` rejection. That is deliberate — the dependency is
/// encoded rather than left to reviewer memory. Land #415 first.
#[test]
fn guarded_pda_bindings_name_a_guard_that_exists() {
    let src = include_str!("../src/v16_program.rs");

    for (binding, guard, guard_fragment) in GUARDED_PDA_BINDINGS {
        assert!(
            src.contains(guard_fragment),
            "`{binding}` is registered as guarded by {guard}, but the source contains no \
             `{guard_fragment}` — so that guard is NOT in this build and the binding is \
             unprotected.\n\n\
             Either land the change that adds the guard before this canary, or remove the \
             entry from GUARDED_PDA_BINDINGS so the binding is reported as unreviewed."
        );
    }
}
