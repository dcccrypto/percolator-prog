You are doing a ship-blocking security audit of this system. Your goal is to find real, major vulnerabilities where user funds can be stolen, permanently frozen, incorrectly redistributed, or rendered unwithdrawable/unclearable.
Scope
Audit the attached spec as the source of truth, and also check the implementation against it where code is provided. Treat any mismatch between spec and implementation as potentially critical. The spec is the normative target and the code may be wrong, incomplete, or stale.    
Core task
Work in a systematic loop over the document/instructions:
1. Go through the spec instruction by instruction / rule by rule / helper by helper / operation by operation.
2. For each item, do a deep adversarial audit focused on:
    * theft of user funds
    * permanent fund lock / bricking
    * bad debt being socialized incorrectly
    * invariant bypass that lets value be minted, destroyed, or trapped
    * liveness failure that makes honest users unable to settle, withdraw, close, liquidate, reclaim, or resolve
    * implementation/spec mismatch that breaks safety assumptions
3. Try to construct a concrete exploit or failure sequence.
4. Then write a test that proves the issue is real.
5. If the test does not actually fail on the claimed bug, or does not distinguish valid behavior from broken behavior, delete that finding and keep searching.
6. Repeat until you have only findings backed by real failing tests or airtight proof sketches.
Required working style
Be extremely skeptical. Do not report hypothetical or “maybe” issues unless you can drive them to one of:
* a reproducible failing test,
* a minimal concrete counterexample,
* or a tight proof that the rule is internally inconsistent and necessarily causes theft/bricking.
Your default assumption should be: most suspected bugs are false until proven.
Loop discipline
For every candidate issue, follow this exact loop:
A. Target
Name the exact rule / helper / instruction / invariant being audited.
B. Threat model
State exactly how funds could be:
* stolen,
* frozen,
* mis-accounted,
* unfairly socialized,
* or made permanently unrecoverable.
C. Exploit path
Give the smallest concrete sequence of actions and state transitions needed to trigger it.
D. Why the current logic allows it
Point to the exact lines / rules / interactions causing the problem.
E. Proof attempt
Produce one of:
* a unit test,
* scenario test,
* property test,
* invariant test,
* model-check style counterexample,
* or step-by-step numeric trace.
F. Verification gate
After writing the test, ask:
* Does this test actually fail for the vulnerable behavior?
* Does it fail for the right reason?
* Would it pass once the bug is fixed?
* Is this truly major, meaning real user funds can be stolen or bricked?
If the answer is not clearly yes, discard the finding.
Severity filter
Only keep issues that are major / ship-blocking:
* direct theft
* permanent withdrawal failure
* permanent close/reclaim/resolve failure
* irreversible accounting corruption
* unauthorized value transfer
* exploitable undercollateralization bypass
* invariant break that can strand or mint material value
* permissionless griefing that can permanently brick market progress or user exits
Do not keep:
* style issues
* naming issues
* gas-only issues
* “could be cleaner”
* minor rounding dust unless it can accumulate into real loss or liveness failure
* wrapper-policy complaints unless the engine/spec claims to protect against them
Important audit angles
Pay extra attention to:
* atomicity mismatches between spec and code
* any path that mutates state before a possible error
* conservation: V >= C_tot + I
* PNL_pos_tot, PNL_matured_pos_tot, R_i, fee debt, insurance
* reserve admission / warmup / touch-time acceleration
* partial liquidation and post-partial health checks
* resolved-mode reconciliation and payout sequencing
* reclaim / close / fee-sync / deposit / pure-capital paths
* OI symmetry and dust/reset lifecycle
* any place where a stale slot, sticky state, or local context can poison later operations
* any place where implementation comments claim safety but logic may differ
* any place where a public path can brick future progress by advancing time/state incorrectly
* any exact arithmetic / overflow / saturation behavior that can change economic outcomes
* spec/code drift between v12.18.5 spec and v12.18.0 implementation
Output format
Keep only validated major findings.
For each kept finding, output:
1. Title
2. Severity
3. What gets stolen/bricked
4. Exact root cause
5. Minimal exploit sequence
6. Why this is real
7. The failing test
8. How to fix it
9. Why the fix closes the exploit
Then include a section:
Discarded candidates
Briefly list suspected issues you investigated but rejected because the proof/test did not hold.
Hard rules
* Do not stop after finding one bug; continue the loop.
* Do not trust comments over logic.
* Do not trust the spec if two spec clauses conflict; treat contradiction as a possible liveness/safety bug.
* Do not keep a finding without proof.
* Do not invent attacks that require violating the stated trust model unless the implementation accidentally enables that violation.
* Prefer minimal concrete counterexamples over long prose.
* Prefer failing tests over intuition.
* If a finding disappears after writing the test, erase it and move on.
* Keep a log of each test and make sure to not repeat yourself.  File: security.md; commit and push it after each test. Delete discarded tests, if you can’t actually prove an issue do not keep the test.

Final objective
Produce the strongest possible list of real, test-backed, ship-blocking issues only. If you cannot prove a candidate, do not report it.

