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
const ALLOWED_RIGHT_HAND_SIDES: [&str; 10] = [
    // Caller-supplied instruction parameters, named at activation or rotation.
    "asset_admin",
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
    "cfg.<field>",
];

/// PDA bindings that are known, reviewed, and individually guarded.
///
/// A binding may only appear here once rotating *away* from it is rejected, because a
/// PDA holder can never sign to defend itself.
const GUARDED_PDA_BINDINGS: [(&str, &str); 1] = [(
    "backing_bucket_authority = registry_pda.to_bytes()",
    "#415: handle_update_asset_authority rejects rotating ASSET_AUTH_BACKING_BUCKET away \
     from an initialised LP vault registry",
)];

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
            // A write (`= value`), never a comparison (`== value`) or a struct-literal
            // field (`field: value`).
            let needle = format!("{field} = ");
            let Some(at) = code.find(&needle) else {
                continue;
            };
            // Reject a longer identifier that merely ends in the same suffix.
            if matches!(code[..at].chars().next_back(), Some(c) if c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            let rhs = normalise_rhs(&code[at + needle.len()..], field);
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
        .map(|(binding, _)| {
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

    for (binding, guard) in GUARDED_PDA_BINDINGS {
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
