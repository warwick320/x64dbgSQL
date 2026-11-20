"""Record the memory of explicitly registered local benchmark processes."""
import argparse
from collections import defaultdict
from contextlib import ExitStack
import ctypes as c
from ctypes import wintypes as w
import json
from pathlib import Path
import time

from measure import measurement_window, read_rows


class Counters(c.Structure):
    _fields_ = [("size", w.DWORD), ("faults", w.DWORD)] + [
        (field, c.c_size_t) for field in (
            "peak_working", "working", "peak_paged_pool", "paged_pool",
            "peak_nonpaged_pool", "nonpaged_pool", "commit", "peak_commit",
            "private",
        )
    ]


kernel = c.WinDLL("kernel32", use_last_error=True)
kernel.OpenProcess.argtypes = (w.DWORD, w.BOOL, w.DWORD)
kernel.OpenProcess.restype = w.HANDLE
kernel.CloseHandle.argtypes = (w.HANDLE,)
kernel.K32GetProcessMemoryInfo.argtypes = (w.HANDLE, c.POINTER(Counters), w.DWORD)
kernel.GetExitCodeProcess.argtypes = (w.HANDLE, c.POINTER(w.DWORD))


def read_registrations(stream):
    """Read new registrations, retaining an unfinished line for the next poll."""
    while True:
        offset = stream.tell()
        line = stream.readline()
        if not line.endswith("\n"):
            stream.seek(offset)
            return
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def sample(run):
    folders = [run / "sql", run / "mcp"]
    handles = {}
    registrations = {}
    try:
        with ExitStack() as readers, (run / "memory.jsonl").open(
            "x", encoding="utf8", buffering=1
        ) as stream:
            while not (run / "memory-stop").exists():
                for lane in folders:
                    if lane not in registrations:
                        try:
                            registry = (lane / "processes.jsonl").open(encoding="utf8")
                        except FileNotFoundError:
                            continue
                        registrations[lane] = readers.enter_context(registry)
                    for process in read_registrations(registrations[lane]):
                        identity = lane.name, process["role"], process["pid"]
                        if identity not in handles:
                            handles[identity] = kernel.OpenProcess(0x1000, False, process["pid"])
                now = time.perf_counter_ns()
                for (lane, role, pid), handle in handles.items():
                    current_exit = w.DWORD()
                    if not handle or not kernel.GetExitCodeProcess(handle, c.byref(current_exit)):
                        continue
                    if current_exit.value != 259:
                        continue
                    stats = Counters(size=c.sizeof(Counters))
                    if kernel.K32GetProcessMemoryInfo(handle, c.byref(stats), c.sizeof(stats)):
                        stream.write(json.dumps({"at_ns": now, "lane": lane, "role": role,
                                                 "pid": pid, "working": stats.working,
                                                 "private": stats.private}) + "\n")
                time.sleep(.25)
    finally:
        for handle in handles.values():
            if handle:
                kernel.CloseHandle(handle)


def process_list(identities):
    return [{"role": role, "pid": pid} for role, pid in sorted(identities)]


def summarize(run):
    now = time.perf_counter_ns()
    bounds = {lane: measurement_window(run / lane, now) for lane in ("sql", "mcp")}
    by_instant = defaultdict(lambda: defaultdict(dict))
    sampled = defaultdict(set)
    roles = defaultdict(dict)
    metrics = ("working", "private")
    log = run / "memory.jsonl"
    log_present = log.exists()
    if log_present:
        for row in read_rows(log):
            lane = row["lane"]
            if lane not in bounds:
                continue
            start, finish, _ = bounds[lane]
            if start is None or not start <= row["at_ns"] <= finish:
                continue
            by_instant[lane][row["at_ns"]][row["pid"]] = row
            sampled[lane].add((row["role"], row["pid"]))
            info = roles[lane].setdefault(row["role"], dict.fromkeys(metrics, 0))
            for metric in metrics:
                info[metric] = max(info[metric], row[metric])

    peaks = {}
    for lane, (_, _, cutoff) in bounds.items():
        snapshots = by_instant[lane]
        registered = {
            (row["role"], row["pid"]) for row in read_rows(run / lane / "processes.jsonl")
        }
        peaks[lane] = {
            "cutoff": cutoff,
            "memory_log_present": log_present,
            "samples": len(snapshots),
            "peak_by_role": roles[lane],
            "registered_processes": process_list(registered),
            "sampled_processes": process_list(sampled[lane]),
            "unsampled_processes": process_list(registered - sampled[lane]),
        }
        for metric in metrics:
            peaks[lane]["peak_combined_" + metric] = max(
                (sum(row[metric] for row in records.values()) for records in snapshots.values()),
                default=None,
            )
    return peaks


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("sample", "report"))
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    if args.operation == "sample":
        sample(args.run)
    else:
        print(json.dumps(summarize(args.run), indent=2))

