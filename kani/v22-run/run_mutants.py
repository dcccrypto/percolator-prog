#!/usr/bin/env python3
"""Kani v2.2 mutant campaign driver (review M12). Runs AFTER the main run, sequentially, never in the
frozen proof worktrees and never with `git stash`.

  python3 run_mutants.py --results <main-run results.tsv> --out <dir> [--queue queue.tsv] [--dry-run]
                         [--only ID[,ID...]] [--allow-pass-nocover]

For every row of the five manifests
  percolator        kani/mutants/v22/engine_core.tsv, kani/mutants/v22/engine_band.tsv
  percolator-prog   kani/mutants/v22/wrapper_ad.tsv,  kani/mutants/v22/wrapper_cfl.tsv
  percolator-stake  kani/mutants/v22/stake.tsv
the row's target harness is resolved to queue rows of the SAME repo by name (`foo(_m)` = `foo` and
`foo_m`; a path hint `kani/<sub>/...` or `kani/<sub>::...` selects that sub-crate, otherwise the repo's
top-level crate; a harness queued in two flavours gives two target runs). A target is run only if its
queue id has status PASS in --results (PASS_NOCOVER too with --allow-pass-nocover); otherwise the
(mutant, target) pair is logged SKIPPED.

Mutant root: <kani-work>/mutants/<repo>/ holds `git worktree add --detach` checkouts of ALL five siblings
at the SHAs in frozen_shas.tsv (so `../percolator` path dependencies resolve). Created once, reused.
Git-ignored Cargo.lock files of queued crates are copied from the frozen trees so dependency versions
match the main run. Per row: every checkout must be at its frozen SHA with a clean `git status
--porcelain`; `mutant.py apply` in the target repo's checkout; each target runs as
  cargo kani <queue row cargo-kani args> --exact --harness <harness>
in the mapped workdir with its own CARGO_TARGET_DIR (<out>/target/<crate>-<flavour>), CARGO_BUILD_JOBS=2,
and run_v22.py's gates, watchdog and RSS cap (its helpers are imported; only our own PID tree is ever
killed); then `mutant.py restore` and the clean check again (a dirty tree stops the campaign).

Status per (mutant, target):
  MUTANT-ERROR       build/compile error, timeout, OOM or any other non-verdict (NOT a kill)
  KILLED             any VERIFICATION FAILED; or, on a cover-targeted row (always S10-G1, W4-S, BND-C2, and any
                     row whose expected-kill text says "unsatisfied"/"unsatisfiable", word match), sum x < sum y
  SURVIVED           SUCCESSFUL with all covers satisfied (or no covers)
  SURVIVED-COVERLOSS SUCCESSFUL, covers lost, but the row is not cover-targeted (not a kill; review it)
  EXPECTED-SURVIVOR  S10-G2 surviving (10-09 ruling); a kill of S10-G2 is logged KILLED and goes back
                     to the reviewer
  SKIPPED            target not PASS in --results (no run)
  UNRESOLVED         target name matches no queue row in the repo (no run)
mutants.tsv: id, repo, file:line, target queue id, status, covers, wall_s, n_verif, verification,
expected_kill, the five checkout SHAs, log. Resume: (id, target) pairs already in mutants.tsv are skipped.
"""
import argparse
import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
KW = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))  # <kani-work>/percolator-prog/kani/v22-run
SIBLINGS = ["percolator", "percolator-prog", "percolator-stake", "percolator-match", "percolator-nft"]
MANIFESTS = [
    ("percolator", "kani/mutants/v22/engine_core.tsv"),
    ("percolator", "kani/mutants/v22/engine_band.tsv"),
    ("percolator-prog", "kani/mutants/v22/wrapper_ad.tsv"),
    ("percolator-prog", "kani/mutants/v22/wrapper_cfl.tsv"),
    ("percolator-stake", "kani/mutants/v22/stake.tsv"),
]
COVER_ALWAYS = {"S10-G1", "W4-S", "BND-C2"}
EXPECTED_SURVIVOR = {"S10-G2"}
MUTANT_PY = os.path.join(HERE, "mutant.py")

sys.dont_write_bytecode = True  # no __pycache__ in the frozen proof worktree (it would count as dirty)
_spec = importlib.util.spec_from_file_location("run_v22", os.path.join(HERE, "run_v22.py"))
rv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rv)


def git(d, *a, check=True):
    p = subprocess.run(["git", "-C", d] + list(a), capture_output=True, text=True)
    if check and p.returncode:
        sys.exit(f"git -C {d} {' '.join(a)} failed: {p.stderr.strip()}")
    return p.stdout.strip()


def read_frozen(path):
    out = {}
    for l in open(path):
        if l.strip() and not l.startswith("#"):
            f = l.split()
            out[f[0]] = f[1]
    missing = [s for s in SIBLINGS if s not in out]
    if missing:
        sys.exit(f"{path}: no frozen sha for {missing}")
    return out


def read_queue(path):
    rows = []
    for l in open(path):
        if not l.strip() or l.startswith("#"):
            continue
        f = l.rstrip("\n").split("\t")
        rel = os.path.relpath(os.path.realpath(f[2]), os.path.realpath(KW))
        rows.append(dict(id=f[0], cls=f[1], wd=f[2], rel=rel, repo=rel.split(os.sep)[0], flav=f[3],
                         harness=f[5], base=f[5].split("::")[-1], args=f[6].split() if len(f) > 6 else []))
    return rows


def read_results(path):
    st = {}
    for l in open(path):
        f = l.rstrip("\n").split("\t")
        if len(f) > 4 and f[0] != "id":
            st[f[0]] = f[4]
    return st


def read_manifest(repo, rel):
    path = os.path.join(KW, repo, rel)
    lines = [l.rstrip("\n") for l in open(path) if l.strip() and not l.startswith("#")]
    hdr = [h.split("(")[0].strip() for h in lines[0].split("\t")]
    ti = hdr.index("target") if "target" in hdr else hdr.index("target_harness")
    ei = next(i for i, h in enumerate(hdr) if h.startswith("expected"))
    for l in lines[1:]:
        f = l.split("\t")
        yield dict(id=f[0], file=f[1], line=f[2], target=f[ti], expected=f[ei], repo=repo, manifest=path)


def target_names(t):
    """('kani/<sub>' or '', [names]) from a manifest target cell."""
    t = t.strip()
    hint, name = (t.rsplit("::", 1) if "::" in t else ("", t))
    m = re.match(r"(kani/[^/:]+)", hint)
    sub = m.group(1) if m else ""
    if name.endswith("(_m)"):
        b = name[: -len("(_m)")]
        return sub, [b, b + "_m"]
    return sub, [name]


def resolve(row, queue):
    sub, names = target_names(row["target"])
    cand = [q for q in queue if q["repo"] == row["repo"] and q["base"] in names]
    if sub:
        cand = [q for q in cand if q["rel"] == os.path.join(row["repo"], sub)]
    else:
        top = [q for q in cand if q["rel"] == row["repo"]]
        cand = top or cand
    return names, cand


UNSAT = re.compile(r"\bunsatisf(ied|iable)\b", re.I)


def cover_targeted(row):
    """Review round 2 N4: a row is cover-targeted only when its designed kill IS a cover becoming
    unsatisfied: the ids in COVER_ALWAYS, or an expected-kill text that says "unsatisfied" /
    "unsatisfiable" (word match). A text that merely names a cover state is NOT cover-targeted."""
    return row["id"] in COVER_ALWAYS or bool(UNSAT.search(row["expected"]))


def mutant_status(row, verdict, x, y):
    if verdict == "FAIL":
        return "KILLED"
    if verdict == "VACUOUS":
        s = "KILLED" if cover_targeted(row) else "SURVIVED-COVERLOSS"
    elif verdict in ("PASS", "PASS_NOCOVER"):
        s = "SURVIVED"
    else:
        return "MUTANT-ERROR"  # ERROR (build/compile), NO-VERDICT, NO-VERDICT-OOM
    if s == "SURVIVED" and row["id"] in EXPECTED_SURVIVOR:
        return "EXPECTED-SURVIVOR"
    return s


# ── mutant roots ──────────────────────────────────────────────────────────────────────────────

def root_of(repo):
    return os.path.join(KW, "mutants", repo)


def ensure_root(repo, frozen, queue):
    """Create (once) <kani-work>/mutants/<repo>/<sibling> detached worktrees at the frozen SHAs."""
    root = root_of(repo)
    os.makedirs(root, exist_ok=True)
    for s in SIBLINGS:
        dst = os.path.join(root, s)
        if not os.path.exists(dst):
            git(os.path.join(KW, s), "worktree", "add", "--detach", dst, frozen[s])
            print(f"  created worktree {dst} @ {frozen[s][:12]}", flush=True)
    # git-ignored lockfiles: copy the frozen tree's so dependency versions match the main run
    for rel in sorted({q["rel"] for q in queue}):
        src = os.path.join(KW, rel, "Cargo.lock")
        dst = os.path.join(root, rel, "Cargo.lock")
        r = rel.split(os.sep)[0]
        if os.path.exists(src) and not os.path.exists(dst) and \
                subprocess.run(["git", "-C", os.path.join(root, r), "check-ignore", "-q",
                                os.path.relpath(dst, os.path.join(root, r))]).returncode == 0:
            shutil.copy2(src, dst)
            print(f"  copied ignored {rel}/Cargo.lock from the frozen tree", flush=True)
    return root


def root_state(root, frozen):
    """[(sibling, sha)] or exit if any checkout is off its frozen sha or dirty."""
    shas = []
    for s in SIBLINGS:
        d = os.path.join(root, s)
        sha = git(d, "rev-parse", "HEAD")
        dirty = git(d, "status", "--porcelain")
        if sha != frozen[s]:
            sys.exit(f"STOP: {d} HEAD {sha} != frozen {frozen[s]}")
        if dirty:
            sys.exit(f"STOP: {d} not clean:\n{dirty}")
        shas.append(sha)
    return shas


def run_target(q, root, out, tag):
    wd = os.path.join(root, q["rel"])
    cmd = ["cargo", "kani"] + q["args"] + ["--exact", "--harness", q["harness"]]
    env = dict(os.environ, CARGO_BUILD_JOBS="2",
               CARGO_TARGET_DIR=os.path.join(out, "target", q["rel"].replace(os.sep, "_") + "-" + q["flav"]))
    logp = os.path.join(out, "logs", tag.replace("/", "_").replace(":", "__") + ".log")
    if not rv.wait_gates(q["cls"], out, tag):
        return None
    t0 = time.time()
    timed_out = oom = False
    with open(logp, "w") as lf:
        lf.write(f"# cmd: {' '.join(cmd)}\n# cwd: {wd}\n# CARGO_TARGET_DIR: {env['CARGO_TARGET_DIR']}\n")
        lf.flush()
        p = subprocess.Popen(cmd, cwd=wd, env=env, stdout=lf, stderr=subprocess.STDOUT)
        try:
            while p.poll() is None:
                time.sleep(5)
                pids, rss, _ = rv.tree_pids(p.pid)
                if sum(rss.get(x, 0) for x in pids) > rv.RSS_CAP_KB[q["cls"]]:
                    oom = True
                    rv.kill_tree(p.pid)
                    break
                if time.time() - t0 > rv.WATCHDOG[q["cls"]]:
                    timed_out = True
                    rv.kill_tree(p.pid)
                    break
        except BaseException:
            rv.kill_tree(p.pid)  # only our own tree
            raise
        p.wait()
    wall = int(time.time() - t0)
    verdict, x, y, n = rv.classify(open(logp, errors="replace").read(), timed_out, oom)
    return verdict, x, y, n, wall, logp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, help="results.tsv of the main run")
    ap.add_argument("--out", required=True)
    ap.add_argument("--queue", default=os.path.join(HERE, "queue.tsv"))
    ap.add_argument("--frozen", required=True, help="the freeze.py output used by the main run")
    ap.add_argument("--only", default="", help="comma list of mutant ids")
    ap.add_argument("--allow-pass-nocover", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    frozen = read_frozen(a.frozen)
    for s in SIBLINGS:  # the frozen proof trees themselves must be at the frozen SHAs
        sha = git(os.path.join(KW, s), "rev-parse", "HEAD")
        if sha != frozen[s]:
            sys.exit(f"frozen tree {KW}/{s} HEAD {sha} != frozen_shas.tsv {frozen[s]}")
    queue = read_queue(a.queue)
    results = read_results(a.results)
    ok_status = {"PASS", "PASS_NOCOVER"} if a.allow_pass_nocover else {"PASS"}
    only = {x for x in a.only.split(",") if x}

    rows = [r for repo, rel in MANIFESTS for r in read_manifest(repo, rel) if not only or r["id"] in only]
    ids = [r["id"] for r in rows]
    dup = {i for i in ids if ids.count(i) > 1}
    if dup:
        sys.exit(f"duplicate mutant ids across manifests: {sorted(dup)}")

    plan = []  # (row, [(q, action)]) ; action RUN / SKIPPED / UNRESOLVED
    for r in rows:
        names, cand = resolve(r, queue)
        if not cand:
            plan.append((r, [(None, "UNRESOLVED")]))
            continue
        plan.append((r, [(q, "RUN" if results.get(q["id"]) in ok_status else "SKIPPED") for q in cand]))

    n_run = sum(1 for _, ts in plan for _, act in ts if act == "RUN")
    n_mut = sum(1 for _, ts in plan if any(act == "RUN" for _, act in ts))
    print(f"{len(rows)} mutant rows, {n_mut} with a runnable target, {n_run} target runs; "
          f"frozen: " + " ".join(f"{s}={frozen[s][:10]}" for s in SIBLINGS), flush=True)

    if a.dry_run:
        print("# id\trepo\tfile:line\tcover_targeted\ttarget_queue_id\tresults_status\taction\tcwd\tcmd")
        for r, ts in plan:
            for q, act in ts:
                if q is None:
                    print("\t".join([r["id"], r["repo"], f"{r['file']}:{r['line']}", str(cover_targeted(r)),
                                     r["target"], "-", act, "-", "-"]))
                    continue
                cwd = os.path.join(root_of(r["repo"]), q["rel"])
                cmd = " ".join(["cargo", "kani"] + q["args"] + ["--exact", "--harness", q["harness"]])
                print("\t".join([r["id"], r["repo"], f"{r['file']}:{r['line']}", str(cover_targeted(r)), q["id"],
                                 results.get(q["id"], "-"), act, cwd, cmd]))
        for repo in sorted({r["repo"] for r, _ in plan}):
            print(f"# mutant root {root_of(repo)}: "
                  + ("exists" if os.path.isdir(root_of(repo)) else "would be created")
                  + " with worktrees " + ", ".join(f"{s}@{frozen[s][:10]}" for s in SIBLINGS))
        return 0

    os.makedirs(os.path.join(a.out, "logs"), exist_ok=True)
    mt = os.path.join(a.out, "mutants.tsv")
    done = set()
    if os.path.exists(mt):
        for l in open(mt):
            f = l.rstrip("\n").split("\t")
            if len(f) > 4 and f[0] != "id":
                done.add((f[0], f[3]))
    else:
        with open(mt, "w") as f:
            f.write("\t".join(["id", "repo", "file:line", "target", "status", "covers", "wall_s", "n_verif",
                               "verification", "expected_kill"] + [f"sha_{s}" for s in SIBLINGS] + ["log"]) + "\n")
    if os.path.exists(os.path.join(a.out, "ALERT")):
        sys.exit(f"{a.out}/ALERT exists: read it, then remove it to resume")

    def log(r, target, status, shas, covers="-", wall="-", n="-", verdict="-", logp="-"):
        with open(mt, "a") as f:
            f.write("\t".join([r["id"], r["repo"], f"{r['file']}:{r['line']}", target, status, covers, str(wall),
                               str(n), verdict, r["expected"]] + shas + [logp]) + "\n")
        print(f"[{time.strftime('%H:%M:%S')}] {r['id']} {target} {status} {covers} {wall}s", flush=True)

    for r, ts in plan:
        todo = [(q, act) for q, act in ts if (r["id"], q["id"] if q else r["target"]) not in done]
        if not todo:
            continue
        root = ensure_root(r["repo"], frozen, queue)
        shas = root_state(root, frozen)
        for q, act in todo:
            if act != "RUN":
                log(r, q["id"] if q else r["target"], act, shas,
                    verdict=(results.get(q["id"], "absent") if q else "-"))
        runs = [q for q, act in todo if act == "RUN"]
        if not runs:
            continue
        rc = subprocess.run([sys.executable, "-I", MUTANT_PY, "apply", r["manifest"], r["id"],
                             os.path.join(root, r["repo"])])
        try:
            if rc.returncode:
                for q in runs:
                    log(r, q["id"], "MUTANT-ERROR", shas, verdict="apply-failed")
                continue
            for q in runs:
                res = run_target(q, root, a.out, f"{r['id']}@{q['id']}")
                if res is None:  # gate ALERT: stop, nothing killed
                    break
                verdict, x, y, n, wall, logp = res
                log(r, q["id"], mutant_status(r, verdict, x, y), shas,
                    covers=f"{x}/{y}" if y is not None else "-", wall=wall, n=n, verdict=verdict, logp=logp)
        finally:
            subprocess.run([sys.executable, "-I", MUTANT_PY, "restore", r["manifest"], r["id"],
                            os.path.join(root, r["repo"])], check=True)
            root_state(root, frozen)  # must be clean and frozen before the next row
        if rv.abort.is_set():
            print(f"ABORTED: see {os.path.join(a.out, 'ALERT')}", flush=True)
            return 3
    print("DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
