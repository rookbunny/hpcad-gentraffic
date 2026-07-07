"""Append-only ground-truth logging.

All output for a run lives in a per-run directory logs/<run_id>_logs/ and every
file inside is prefixed with the run id:

  <run_id>_knownbenign.json  scripted benign generator events
  <run_id>_knownuser.json    human/manual events (attacker actions, web browsing)
  <run_id>_alltraffic.json   union of both

Files are newline-delimited JSON (one record per line). Writes use a single
os.write() to an O_APPEND descriptor, which is atomic for records below the
pipe-buffer size, so multiple threads AND multiple processes (the generator and
the manual logger running at once during a run) can append without interleaving.
"""
import json, os

def run_dir_for(base, run_id):
    return os.path.join(base, "logs", f"{run_id}_logs")

def _path(run_dir, run_id, suffix):
    return os.path.join(run_dir, f"{run_id}_{suffix}.json")

def atomic_append(path, obj):
    line = (json.dumps(obj) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, line)   # single write < PIPE_BUF -> atomic across processes
    finally:
        os.close(fd)

def write_benign(run_dir, run_id, record):
    os.makedirs(run_dir, exist_ok=True)
    record.setdefault("class", "benign")
    atomic_append(_path(run_dir, run_id, "knownbenign"), record)
    atomic_append(_path(run_dir, run_id, "alltraffic"), record)

def write_user(run_dir, run_id, record):
    os.makedirs(run_dir, exist_ok=True)
    record.setdefault("class", "user")
    atomic_append(_path(run_dir, run_id, "knownuser"), record)
    atomic_append(_path(run_dir, run_id, "alltraffic"), record)
