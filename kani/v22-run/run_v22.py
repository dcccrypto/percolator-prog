#!/usr/bin/env python3
"""Kani v2.2 final-run campaign runner (design rev 2 / rev 2.1, section R4.3-R4.4).

ONE run. Reads queue.tsv, runs each harness once, never re-runs a harness that has a row in
results.tsv (resume after a restart only), never stops at a FAILED, never edits code.

  python3 run_v22.py --queue queue.tsv --out <results dir> [--dry-run]

queue.tsv columns (tab-separated, '#' comments):
  id  class(S|M|L)  workdir(absolute)  flavour  deps(comma list of ids or -)  harness  cargo-kani-args...
The command run is:  cargo kani <cargo-kani-args> --exact --harness <harness>   (in <workdir>)

Machine rules (CLAUDE memory: fan-out limits, kill by PID only):
  * start only when the 5-min load average < 8 and >= 40 GB disk is free;
  * before every harness wait (never kill anything) while 5-min load > 16 or disk < 40 GB;
  * before an L harness wait until >= 24 GB physical memory is free; at most one L at a time;
  * 3 lanes, each with its own CARGO_TARGET_DIR; CARGO_BUILD_JOBS=2;
  * RSS cap on the runner's OWN process tree: 16 GB (L) / 8 GB (S, M) -> kill that tree -> NO-VERDICT-OOM;
  * watchdog S 600 s, M 1800 s, L 4000 s -> kill own tree -> NO-VERDICT (unless a verdict was already printed);
  * while waiting on a gate, log the reason (load/disk/mem) every 10 min; after 6 h of CONTINUOUS waiting write
    <out>/ALERT, start no further harness (running ones finish; nothing is killed) and exit non-zero (3);
  * at start every queue workdir's repo HEAD must equal its row in frozen_shas.tsv (repo dir name -> sha).

Verdicts (M5): one invocation can verify several harnesses (same name in two test targets), so the log is
classified as a whole: FAIL if ANY `VERIFICATION:- FAILED`; covers are summed over every
"x of y cover properties satisfied" line (VACUOUS if sum x < sum y); the number of VERIFICATION lines is a
results column (n_verif) and fewer verdicts than `Checking harness` lines is never a PASS.
"""
import argparse, os, re, shutil, signal, subprocess, sys, threading, time

WATCHDOG = {"S": 600, "M": 1800, "L": 4000}
RSS_CAP_KB = {"S": 8 << 20, "M": 8 << 20, "L": 16 << 20}
LANES = 3
GB = 1 << 30

WAIT_LOG_S = 600
WAIT_ALERT_S = 6 * 3600
HERE = os.path.dirname(os.path.abspath(__file__))

lock = threading.Lock()
heavy = threading.Semaphore(1)
abort = threading.Event()  # set once a gate has been waited on for WAIT_ALERT_S


def load5():
    return os.getloadavg()[1]


def disk_free_gb(path):
    return shutil.disk_usage(path).free / GB


def mem_free_gb():
    out = subprocess.run(["vm_stat"], capture_output=True, text=True).stdout
    page = int(re.search(r"page size of (\d+)", out).group(1))
    def pages(k):
        m = re.search(k + r":\s+(\d+)", out)
        return int(m.group(1)) if m else 0
    return (pages("Pages free") + pages("Pages inactive") + pages("Pages speculative")) * page / GB


def tree_pids(root):
    out = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,rss=,comm="], capture_output=True, text=True).stdout
    kids, rss, comm = {}, {}, {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        pid, ppid, r = int(parts[0]), int(parts[1]), int(parts[2])
        kids.setdefault(ppid, []).append(pid)
        rss[pid] = r
        comm[pid] = parts[3] if len(parts) > 3 else ""
    seen, stack = [], [root]
    while stack:
        p = stack.pop()
        seen.append(p)
        stack.extend(kids.get(p, []))
    return seen, rss, comm


def kill_tree(root):
    pids, _, _ = tree_pids(root)
    for p in reversed(pids):  # children first; only PIDs of OUR tree
        try:
            os.kill(p, signal.SIGKILL)
        except ProcessLookupError:
            pass


def gate_state(cls, outdir, max_load=16):
    """(ok, reason) for the machine gates. mem is checked only for L (call it AFTER heavy.acquire())."""
    l, d = load5(), disk_free_gb(outdir)
    m = mem_free_gb() if cls == "L" else None
    why = []
    if l > max_load:
        why.append(f"load5={l:.1f}>{max_load}")
    if d < 40:
        why.append(f"disk={d:.1f}GB<40")
    if m is not None and m < 24:
        why.append(f"mem={m:.1f}GB<24")
    vals = f"load5={l:.1f} disk={d:.1f}GB" + (f" mem={m:.1f}GB" if m is not None else "")
    return (not why), ("; ".join(why) + " | " + vals)


def raise_alert(outdir, what, waited):
    msg = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} ALERT: waited {waited / 3600:.1f} h continuously on gates "
           f"({what}). The runner starts no further harness and exits 3; nothing was killed.\n")
    with lock:
        with open(os.path.join(outdir, "ALERT"), "a") as f:
            f.write(msg)
        print(msg, end="", flush=True)
    abort.set()


def wait_gates(cls, outdir, tag, max_load=16, poll=30):
    """Block until the gates pass. Returns False (and sets `abort`) after WAIT_ALERT_S of continuous waiting."""
    t0 = time.time()
    last_log = None
    while True:
        if abort.is_set():
            return False
        ok, what = gate_state(cls, outdir, max_load)
        if ok:
            if last_log is not None:
                print(f"[{time.strftime('%H:%M:%S')}] {tag}: gates clear after {int(time.time() - t0)}s ({what})", flush=True)
            return True
        now = time.time()
        if last_log is None or now - last_log >= WAIT_LOG_S:
            print(f"[{time.strftime('%H:%M:%S')}] {tag}: waiting {int(now - t0)}s: {what}", flush=True)
            last_log = now
        if now - t0 >= WAIT_ALERT_S:
            raise_alert(outdir, f"{tag}: {what}", now - t0)
            return False
        time.sleep(poll)


def classify(log, timed_out, oom):
    """(status, sum_x, sum_y, n_verif) over the WHOLE log (M5).

    FAIL if any VERIFICATION line says FAILED. Otherwise PASS needs every started harness to have a
    SUCCESSFUL verdict (n_verif >= number of `Checking harness` lines) and sum x == sum y over all cover
    summaries; sum x < sum y is VACUOUS; no cover summary (or sum y == 0) is PASS_NOCOVER."""
    v = re.findall(r"^VERIFICATION:-\s*(\w+)", log, re.M)
    cov = re.findall(r"\*\*\s*(\d+) of (\d+) cover properties satisfied", log)
    started = len(re.findall(r"^Checking harness ", log, re.M))
    n = len(v)
    x = sum(int(a) for a, _ in cov) if cov else None
    y = sum(int(b) for _, b in cov) if cov else None
    if "FAILED" in v:
        return "FAIL", x, y, n
    if n and all(w == "SUCCESSFUL" for w in v) and n >= started:
        if y is None or y == 0:
            return "PASS_NOCOVER", x, y, n
        return ("PASS" if x == y else "VACUOUS"), x, y, n
    if oom:
        return "NO-VERDICT-OOM", x, y, n
    if timed_out:
        return "NO-VERDICT", x, y, n
    return "ERROR", x, y, n


def run_one(job, outdir, lane):
    hid, cls, wd, flav, deps, harness, args = job
    if cls == "L":
        heavy.acquire()  # at most one L; its free-memory gate is checked only once it holds the slot
    try:
        if not wait_gates(cls, outdir, f"lane{lane} {hid}"):
            return
        env = dict(os.environ, CARGO_BUILD_JOBS="2",
                   CARGO_TARGET_DIR=os.path.join(outdir, "target", f"lane{lane}", os.path.basename(wd.rstrip('/')) + "-" + flav))
        cmd = ["cargo", "kani"] + args + ["--exact", "--harness", harness]
        logp = os.path.join(outdir, "logs", hid + ".log")
        t0 = time.time()
        with open(logp, "w") as lf:
            lf.write("# cmd: " + " ".join(cmd) + "\n# cwd: " + wd + "\n")
            lf.flush()
            p = subprocess.Popen(cmd, cwd=wd, env=env, stdout=lf, stderr=subprocess.STDOUT)
            timed_out = oom = False
            while p.poll() is None:
                time.sleep(5)
                pids, rss, _ = tree_pids(p.pid)
                if sum(rss.get(q, 0) for q in pids) > RSS_CAP_KB[cls]:
                    oom = True
                    kill_tree(p.pid)
                    break
                if time.time() - t0 > WATCHDOG[cls]:
                    timed_out = True
                    kill_tree(p.pid)
                    break
            p.wait()
        wall = int(time.time() - t0)
        log = open(logp, errors="replace").read()
        status, x, y, nverif = classify(log, timed_out, oom)
        failed = re.findall(r"(\d+) of \d+ failed", log)
        sha = subprocess.run(["git", "-C", wd, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        dirty = len(subprocess.run(["git", "-C", wd, "status", "--porcelain"], capture_output=True, text=True).stdout.splitlines())
        row = [hid, cls, flav, harness, status, f"{x}/{y}" if y is not None else "-", failed[-1] if failed else "-",
               str(wall), sha, str(dirty), deps, " ".join(cmd), wd, str(nverif)]
        with lock:
            with open(os.path.join(outdir, "results.tsv"), "a") as rf:
                rf.write("\t".join(row) + "\n")
            print(f"[{time.strftime('%H:%M:%S')}] lane{lane} {hid} {status} {row[5]} {wall}s", flush=True)
    finally:
        if cls == "L":
            heavy.release()


def repo_head(wd):
    top = subprocess.run(["git", "-C", wd, "rev-parse", "--show-toplevel"], capture_output=True, text=True).stdout.strip()
    sha = subprocess.run(["git", "-C", wd, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    return os.path.basename(top), sha


def check_frozen(path, workdirs):
    """Abort unless every queue workdir's repo HEAD equals its frozen sha (repo dir name -> sha)."""
    frozen = {}
    for l in open(path):
        if l.strip() and not l.startswith("#"):
            f = l.split()
            frozen[f[0]] = f[1]
    bad = []
    for wd in sorted(workdirs):
        repo, sha = repo_head(wd)
        want = frozen.get(repo)
        if want is None:
            bad.append(f"{wd}: repo {repo!r} not in {path}")
        elif not sha or not (sha.startswith(want) or want.startswith(sha)):
            bad.append(f"{wd}: HEAD {sha or '?'} != frozen {want} ({repo})")
    if bad:
        sys.exit("frozen-SHA check FAILED:\n  " + "\n  ".join(bad))
    print(f"frozen-SHA check ok: {len(workdirs)} workdirs match {path}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--frozen", required=True,
                    help="repo dir name -> frozen sha, written by freeze.py at freeze time (outside the repos: a\n"
                         "file committed here could never hold its own commit's sha)")
    a = ap.parse_args()
    os.makedirs(os.path.join(a.out, "logs"), exist_ok=True)
    jobs = []
    ids = set()
    for line in open(a.queue):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        hid, cls, wd, flav, deps, harness = f[:6]
        assert cls in WATCHDOG, line
        assert hid not in ids, "duplicate id " + hid
        ids.add(hid)
        jobs.append((hid, cls, wd, flav, deps, harness, f[6].split() if len(f) > 6 else []))
    check_frozen(a.frozen, {j[2] for j in jobs})
    resf = os.path.join(a.out, "results.tsv")
    done = set()
    if os.path.exists(resf):
        done = {l.split("\t")[0] for l in open(resf) if l.strip()}
    else:
        open(resf, "w").write("id\tclass\tflavour\tharness\tstatus\tcovers\tfailed\twall_s\tsha\tdirty\tdeps\tcmd\tcwd\tn_verif\n")
    order = {"S": 0, "M": 1, "L": 2}
    # dependencies first (lemma/contract harnesses), then by class
    depset = {d for j in jobs for d in (j[4].split(",") if j[4] != "-" else [])}
    jobs.sort(key=lambda j: (0 if j[0] in depset else 1, order[j[1]]))
    todo = [j for j in jobs if j[0] not in done]
    print(f"{len(jobs)} queued, {len(done)} already recorded, {len(todo)} to run", flush=True)
    if a.dry_run:
        for j in todo:
            print("\t".join([j[0], j[1], j[3], j[5], j[2]] + j[6]))
        return
    if os.path.exists(os.path.join(a.out, "ALERT")):
        sys.exit(f"{a.out}/ALERT exists: read it, then remove it to resume")
    if not wait_gates("S", a.out, "start", max_load=8, poll=60):  # start gate: load5 < 8, disk >= 40 GB
        sys.exit(3)
    it = iter(todo)
    itlock = threading.Lock()

    def lane_worker(n):
        while True:
            if abort.is_set():
                return
            with itlock:
                j = next(it, None)
            if j is None:
                return
            run_one(j, a.out, n)

    ts = [threading.Thread(target=lane_worker, args=(n,)) for n in range(LANES)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if abort.is_set():
        print(f"ABORTED: see {os.path.join(a.out, 'ALERT')}", flush=True)
        sys.exit(3)
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
