#!/usr/bin/env python3
"""Run ONE Kani harness with a watchdog + RSS cap; append a TSV row to <logdir>/SUMMARY.tsv.

usage: kh.py <crate_dir> <harness> <limit_s> <logdir> [extra cargo-kani args...]
env:   KH_RSS_GB (default 12)  -- kill the job's process group above this RSS (NO-VERDICT-OOM)
       KH_SLOTS  (default 4)   -- session-wide concurrency: at most this many kh.py jobs run at
                                  once (flock on ~/wt-v22-kani2/tools/slot<i>.lock); others wait.
Admission: waits until load5 <= KH_LOAD (default 55) and free+inactive memory >= KH_RSS_GB + 2 GB.
Kills only the process group it created. TIMEOUT/OOM is NO-VERDICT, never a pass.
Verdict: PASS only if VERIFICATION:- SUCCESSFUL and every cover is satisfied.
"""
import fcntl, os, re, signal, subprocess, sys, time

crate, harness, limit, logdir = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
extra = sys.argv[5:]
rss_cap = float(os.environ.get("KH_RSS_GB", "12")) * 2**30
slots = int(os.environ.get("KH_SLOTS", "4"))
tools = os.path.dirname(os.path.abspath(__file__))
os.makedirs(logdir, exist_ok=True)
sfx = ("." + extra[extra.index("--solver") + 1]) if "--solver" in extra else ""
log = os.path.join(logdir, harness.replace("::", "__") + sfx + ".log")


def free_bytes():
    out = subprocess.run(["vm_stat"], capture_output=True, text=True).stdout
    pg = int(re.search(r"page size of (\d+)", out).group(1))
    n = 0
    for k in ("Pages free", "Pages inactive", "Pages speculative"):
        m = re.search(k + r":\s+(\d+)", out)
        n += int(m.group(1)) if m else 0
    return n * pg


def load5():
    return float(subprocess.run(["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True).stdout.split()[2])


def group_rss(pgid):
    out = subprocess.run(["ps", "-A", "-o", "pgid=,rss="], capture_output=True, text=True).stdout
    t = 0
    for line in out.splitlines():
        a = line.split()
        if len(a) == 2 and int(a[0]) == pgid:
            t += int(a[1]) * 1024
    return t


def gate_ok():
    return load5() <= float(os.environ.get("KH_LOAD", "55")) and free_bytes() >= rss_cap + 2 * 2**30


# admission gate first (without holding a slot), then a session-wide slot, then re-check
lockf = None
while lockf is None:
    while not gate_ok():
        time.sleep(20)
    for i in range(slots):
        f = open(os.path.join(tools, "slot%d.lock" % i), "w")
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            lockf = f
            break
        except OSError:
            f.close()
    if lockf is not None and not gate_ok():
        lockf.close()
        lockf = None
    if lockf is None:
        time.sleep(15)

cmd = ["nice", "cargo", "kani", *extra, "--harness", harness, "--exact"]
t0 = time.time()
peak = 0
oom = timed_out = False
with open(log, "w") as f:
    f.write("# cwd=%s\n# cmd=%s\n" % (os.path.abspath(crate), " ".join(cmd)))
    f.flush()
    p = subprocess.Popen(cmd, cwd=crate, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
    while True:
        try:
            rc = p.wait(timeout=5)
            break
        except subprocess.TimeoutExpired:
            r = group_rss(p.pid)
            peak = max(peak, r)
            if r > rss_cap:
                oom = True
            elif time.time() - t0 > limit:
                timed_out = True
            if oom or timed_out:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
                rc = -9
                break
wall = int(time.time() - t0)
txt = open(log, errors="replace").read()
cov = re.findall(r"(\d+) of (\d+) cover properties satisfied", txt)
covs = "%s/%s" % cov[-1] if cov else "-"
nfail = len(re.findall(r"Status: FAILURE", txt))
if oom:
    st = "NO-VERDICT-OOM(%.0fGB)" % (rss_cap / 2**30)
elif timed_out:
    st = "NO-VERDICT(timeout %ds)" % limit
elif "VERIFICATION:- SUCCESSFUL" in txt:
    st = "PASS" if (cov and cov[-1][0] == cov[-1][1]) else "PASS_NOCOVER"
elif "VERIFICATION:- FAILED" in txt:
    st = "FAIL"
elif re.search(r"^error", txt, re.M):
    st = "BUILD-ERROR"
else:
    st = "NO-VERDICT(rc=%d)" % rc
row = "\t".join([time.strftime("%H:%M:%S"), harness, st, covs, str(nfail), str(wall),
                 "%.1fGB" % (peak / 2**30), os.path.abspath(crate), " ".join(extra)])
with open(os.path.join(logdir, "SUMMARY.tsv"), "a") as s:
    s.write(row + "\n")
print(row, flush=True)
