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
  * watchdog S 600 s, M 1800 s, L 4000 s -> kill own tree -> NO-VERDICT (unless a verdict was already printed).
"""
import argparse, os, re, shutil, signal, subprocess, sys, threading, time

WATCHDOG = {"S": 600, "M": 1800, "L": 4000}
RSS_CAP_KB = {"S": 8 << 20, "M": 8 << 20, "L": 16 << 20}
LANES = 3
GB = 1 << 30

lock = threading.Lock()
heavy = threading.Semaphore(1)


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


def wait_gates(cls, outdir):
    while True:
        ok = load5() <= 16 and disk_free_gb(outdir) >= 40
        if ok and cls == "L":
            ok = mem_free_gb() >= 24
        if ok:
            return
        time.sleep(30)


def classify(log, timed_out, oom):
    v = re.findall(r"^VERIFICATION:-\s*(\w+)", log, re.M)
    cov = re.findall(r"\*\*\s*(\d+) of (\d+) cover properties satisfied", log)
    verdict = v[-1] if v else None
    x, y = (int(cov[-1][0]), int(cov[-1][1])) if cov else (None, None)
    if verdict == "SUCCESSFUL":
        if y is None or y == 0:
            return "PASS_NOCOVER", x, y
        return ("PASS" if x == y else "VACUOUS"), x, y
    if verdict == "FAILED":
        return "FAIL", x, y
    if oom:
        return "NO-VERDICT-OOM", x, y
    if timed_out:
        return "NO-VERDICT", x, y
    return "ERROR", x, y


def run_one(job, outdir, lane):
    hid, cls, wd, flav, deps, harness, args = job
    wait_gates(cls, outdir)
    if cls == "L":
        heavy.acquire()
    try:
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
        status, x, y = classify(log, timed_out, oom)
        failed = re.findall(r"(\d+) of \d+ failed", log)
        sha = subprocess.run(["git", "-C", wd, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        dirty = len(subprocess.run(["git", "-C", wd, "status", "--porcelain"], capture_output=True, text=True).stdout.splitlines())
        row = [hid, cls, flav, harness, status, f"{x}/{y}" if y is not None else "-", failed[-1] if failed else "-",
               str(wall), sha, str(dirty), deps, " ".join(cmd), wd]
        with lock:
            with open(os.path.join(outdir, "results.tsv"), "a") as rf:
                rf.write("\t".join(row) + "\n")
            print(f"[{time.strftime('%H:%M:%S')}] lane{lane} {hid} {status} {row[5]} {wall}s", flush=True)
    finally:
        if cls == "L":
            heavy.release()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queue", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dry-run", action="store_true")
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
    resf = os.path.join(a.out, "results.tsv")
    done = set()
    if os.path.exists(resf):
        done = {l.split("\t")[0] for l in open(resf) if l.strip()}
    else:
        open(resf, "w").write("id\tclass\tflavour\tharness\tstatus\tcovers\tfailed\twall_s\tsha\tdirty\tdeps\tcmd\tcwd\n")
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
    while load5() >= 8 or disk_free_gb(a.out) < 40:
        print(f"waiting to start: load5={load5():.1f} disk={disk_free_gb(a.out):.0f}GB", flush=True)
        time.sleep(60)
    it = iter(todo)
    itlock = threading.Lock()

    def lane_worker(n):
        while True:
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
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
