"""Append-only ground-truth logging.

A run is identified by a sequential run id (0001, 0002, ...) and a 5-digit seed.
On disk both are folded into a single stem, the run tag R<run_id>-S<seed> (e.g.
R0001-S12345). All output for a run lives in a per-run directory
logs/<tag>_logs/ and every file inside is prefixed with the tag:

  <tag>_knownbenign.json  scripted benign generator events + real Zabbix packets
  <tag>_knownuser.json    human/manual events (attacker actions, web browsing)
  <tag>_knownzabbix.json  the real Zabbix agent's traffic, one record per packet
  <tag>_alltraffic.json   union of the benign and user classes

A Zabbix record is written to knownzabbix (its own view of that stream) AND to
knownbenign (the holistic union of everything known-benign) AND to alltraffic
(the union of everything), one copy in each: knownzabbix is a subset of
knownbenign, exactly as knownbenign is a subset of alltraffic, so
knownbenign + knownuser == alltraffic still holds with the Zabbix stream folded
in. Nothing is counted twice.

Files are newline-delimited JSON (one record per line). Writes use a single
os.write() to an O_APPEND descriptor, which is atomic for records below the
pipe-buffer size, so multiple threads AND multiple processes (the generator and
the manual logger running at once during a run) can append without interleaving.
"""
import json, os, re

_TAG_RE = re.compile(r"^R(?P<run_id>[^-]+)-S(?P<seed>.+)$")

def tag_for(run_id, seed):
    """Filesystem stem for a run: R<run_id>-S<seed>."""
    return f"R{run_id}-S{seed}"

def parse_tag(tag):
    """Split an R<run_id>-S<seed> stem into (run_id, seed); (tag, None) if it doesn't match."""
    m = _TAG_RE.match(tag)
    if not m:
        return tag, None
    return m.group("run_id"), m.group("seed")

def next_run_id(base):
    """Next zero-padded sequential run id (0001, 0002, ...) by scanning logs/."""
    logs = os.path.join(base, "logs")
    n = 0
    if os.path.isdir(logs):
        for name in os.listdir(logs):
            m = re.match(r"R(\d+)-S\d+_logs$", name)
            if m:
                n = max(n, int(m.group(1)))
    return f"{n + 1:04d}"

def run_dir_for(base, tag):
    return os.path.join(base, "logs", f"{tag}_logs")

def _path(run_dir, tag, suffix):
    return os.path.join(run_dir, f"{tag}_{suffix}.json")

def atomic_append(path, obj):
    line = (json.dumps(obj) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line)   # single write < PIPE_BUF -> atomic across processes
    finally:
        os.close(fd)

def write_benign(run_dir, tag, record):
    os.makedirs(run_dir, exist_ok=True)
    record.setdefault("class", "benign")
    atomic_append(_path(run_dir, tag, "knownbenign"), record)
    atomic_append(_path(run_dir, tag, "alltraffic"), record)

def write_user(run_dir, tag, record):
    os.makedirs(run_dir, exist_ok=True)
    record.setdefault("class", "user")
    atomic_append(_path(run_dir, tag, "knownuser"), record)
    atomic_append(_path(run_dir, tag, "alltraffic"), record)

def write_zabbix(run_dir, tag, record):
    """One packet of real Zabbix traffic: its own log, plus both unions.

    Zabbix is benign by class, so it belongs in knownbenign and therefore in
    alltraffic; knownzabbix is the separate per-stream view (see the module
    docstring). The generator never writes here -- no Zabbix traffic is
    simulated; zabbix_log.py records what the real agent daemon actually sends.
    """
    os.makedirs(run_dir, exist_ok=True)
    record.setdefault("class", "benign")
    record.setdefault("source", "zabbix_agent")
    atomic_append(_path(run_dir, tag, "knownzabbix"), record)
    atomic_append(_path(run_dir, tag, "knownbenign"), record)
    atomic_append(_path(run_dir, tag, "alltraffic"), record)
