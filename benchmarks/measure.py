"""Monotonic measurements and normal-I/O verification for prepared benchmark trials."""
import argparse
from collections import Counter, defaultdict
from contextlib import contextmanager
import json
from math import ceil
import os
from pathlib import Path
from queue import Empty, Queue
import subprocess
from tempfile import NamedTemporaryFile
import threading
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener

from prepare import digest


class Trial:
    def __init__(self, lane):
        self.lane = Path(lane).resolve()
        manifest = json.loads((self.lane.parent / "preflight.json").read_text(encoding="utf8"))
        self.setup = manifest["lanes"][self.lane.name]
        self.expected_sha = manifest["sample_sha256"]
        self.requests = self.lane / "requests.jsonl"

    def stamp(self, marker):
        path = self.lane / f"{marker}.json"
        write_marker(path, {"at_ns": time.perf_counter_ns(), "utc_ns": time.time_ns()})

    def track(self, role, pid):
        with (self.lane / "processes.jsonl").open("a", encoding="utf8") as stream:
            stream.write(json.dumps({"role": role, "pid": int(pid)}) + "\n")

    def call(self, api, operation, invoke, *, notify=False):
        start = time.perf_counter_ns()
        complete = False
        outcome = "client_error"
        result = None
        try:
            result = invoke()
            complete = True
            return result
        except (TimeoutError, subprocess.TimeoutExpired):
            outcome = "timeout"
            raise
        except URLError as error:
            if isinstance(error.reason, TimeoutError):
                outcome = "timeout"
            raise
        except KeyboardInterrupt:
            outcome = "interrupted"
            raise
        finally:
            end = time.perf_counter_ns()
            if complete:
                outcome = "notification" if notify else response_outcome(result)
            if isinstance(result, subprocess.CompletedProcess):
                size = len(result.stdout.encode("utf8"))
            elif result is not None:
                size = len(json.dumps(result, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf8"))
            else:
                size = 0
            with self.requests.open("a", encoding="utf8") as stream:
                stream.write(json.dumps({"api": api, "operation": operation,
                                         "start_ns": start, "end_ns": end,
                                         "received_response": complete,
                                         "response_bytes": size, "outcome": outcome}) + "\n")

    def sql(self, *args):
        def invoke():
            result = subprocess.run(
                [self.setup["cli"], *args], capture_output=True, encoding="utf8",
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=28)
            return json.loads(result.stdout)
        return self.call("sql_cli", args[0], invoke)

    @contextmanager
    def sql_session(self, *args):
        with subprocess.Popen(
            [self.setup["cli"], "mcp", "--compact", *args], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, encoding="utf8",
            creationflags=subprocess.CREATE_NO_WINDOW,
        ) as cli:
            self.track("sql_stdio", cli.pid)
            lines = Queue()

            def read():
                for line in cli.stdout:
                    lines.put(line)

            threading.Thread(target=read, daemon=True).start()
            try:
                def exchange(message):
                    cli.stdin.write(json.dumps(message) + "\n")
                    cli.stdin.flush()
                    if "id" not in message:
                        return None
                    try:
                        return json.loads(lines.get(timeout=28))
                    except Empty as error:
                        raise TimeoutError("x64dbgSQL stdio response timed out") from error
                yield Rpc("sql_stdio", self, exchange)
            finally:
                cli.stdin.close()
                try:
                    cli.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    cli.kill()
                    cli.wait()

    def mcp_session(self):
        config = json.loads(Path(self.setup["host"]).with_name(
            "mcp_config.json").read_text(encoding="ascii"))
        if config["IpAddress"] != "127.0.0.1":
            raise ValueError("Benchmark endpoint must be local")
        opener = build_opener(ProxyHandler({}))

        def exchange(message):
            request = Request(f"http://127.0.0.1:{config['Port']}/",
                              data=json.dumps(message).encode("utf8"),
                              headers={"Content-Type": "application/json",
                                       "Accept": "application/json, text/event-stream",
                                       "Authorization": "Bearer " + config["AuthToken"]})
            with opener.open(request, timeout=28) as response:
                body = response.read().decode("utf8")
                if "text/event-stream" in response.headers.get("Content-Type", ""):
                    body = next(line.removeprefix("data: ") for line in body.splitlines()
                                if line.startswith("data: "))
                return json.loads(body) if body else None
        return Rpc("x64dbg_mcp", self, exchange)

    def verify(self, accepted, rejected, success_marker, rejection_marker):
        sample = Path(self.setup["sample"])
        before = digest(sample)
        if before != self.expected_sha:
            raise ValueError("Sample bytes differ from preflight")
        if not success_marker.strip() or not rejection_marker.strip():
            raise ValueError("Nonempty expected output markers are required")
        outcomes = {}
        for label, entry, marker in (
            ("accepted", accepted, success_marker), ("rejected", rejected, rejection_marker)
        ):
            result = self.call("verification", label, lambda: subprocess.run(
                [sample], cwd=self.lane, input=entry, capture_output=True,
                encoding="utf8", errors="replace", timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW))
            outcomes[label] = {"exit": result.returncode, "marker": marker,
                               "marker_seen": marker in result.stdout}
        after = digest(sample)
        success = (before == after and outcomes["accepted"]["exit"] == 0
                   and outcomes["rejected"]["exit"] != 0
                   and all(result["marker_seen"] for result in outcomes.values()))
        report = {"at_ns": time.perf_counter_ns(), "utc_ns": time.time_ns(),
                  "success": success,
                  "sha256_before": before, "sha256_after": after, **outcomes}
        name = "proof.json" if success else "last-attempt.json"
        write_marker(self.lane / name, report, exclusive=success, indent=2)
        return report


class Rpc:
    def __init__(self, api, trial, exchange):
        self.api = api
        self.trial = trial
        self.exchange = exchange
        self.sequence = 0

    def request(self, method, params=None, *, notify=False):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        if not notify:
            self.sequence += 1
            message["id"] = self.sequence
        label = params["name"] if method == "tools/call" else method
        return self.trial.call(self.api, label, lambda: self.exchange(message), notify=notify)

    def initialize(self):
        protocol = "2024-11-05" if self.api == "x64dbg_mcp" else "2025-11-25"
        reply = self.request("initialize", {"protocolVersion": protocol,
                                           "capabilities": {}, "clientInfo": {
                                               "name": "release-benchmark", "version": "1"}})
        assert reply["result"]["protocolVersion"] == protocol, reply
        self.request("notifications/initialized", notify=True)

    def tool(self, name, **arguments):
        reply = self.request("tools/call", {"name": name, "arguments": arguments})
        if "error" in reply:
            raise RuntimeError(reply["error"])
        return reply["result"]


def response_outcome(result):
    if result is None:
        return "client_error"
    if isinstance(result, dict):
        nested = result.get("result")
        if (result.get("error") is not None or result.get("ok") is False
                or isinstance(nested, dict) and nested.get("isError") is True):
            return "response_error"
    return "response"


def write_marker(path, data, *, exclusive=True, indent=None):
    # A concurrent report should see either the complete marker or no marker.
    temp = None
    try:
        with NamedTemporaryFile(dir=path.parent, mode="w", encoding="utf8",
                                delete=False) as stream:
            temp = Path(stream.name)
            json.dump(data, stream, indent=indent)
        if not exclusive:
            temp.replace(path)
        elif os.name == "nt":
            temp.rename(path)  # Windows rename rejects an existing destination.
        else:
            os.link(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def read_marker(lane, name):
    try:
        return json.loads((lane / f"{name}.json").read_text(encoding="utf8"))
    except FileNotFoundError:
        return None


def measurement_window(lane, now_ns=None):
    start = read_marker(lane, "start")
    if start is None:
        return None, None, "not_started"
    proof = read_marker(lane, "proof")
    if proof and proof["success"]:
        end, cutoff = proof["at_ns"], "proof"
    elif (stop := read_marker(lane, "stop")) is not None:
        end, cutoff = stop["at_ns"], "stop"
    else:
        end = time.perf_counter_ns() if now_ns is None else now_ns
        cutoff = "report_time"
        if end < start["at_ns"]:
            return None, None, "not_started"
    if end < start["at_ns"]:
        raise ValueError(f"Measurement cutoff precedes start in {lane}")
    return start["at_ns"], end, cutoff


def read_rows(path):
    try:
        stream = path.open(encoding="utf8")
    except FileNotFoundError:
        return
    with stream:
        for line in stream:
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                if line.endswith("\n"):
                    raise
                # A writer may still be appending the last row.


def union_seconds(intervals):
    total = 0
    previous_end = None
    for start, end in sorted(intervals):
        uncovered_start = start if previous_end is None else max(start, previous_end)
        if end > uncovered_start:
            total += end - uncovered_start
        previous_end = end if previous_end is None else max(end, previous_end)
    return total / 1e9


def summarize(trial, now_ns=None):
    lane = trial.lane
    start, end, cutoff = measurement_window(lane, now_ns)
    proof_path = lane / "proof.json"
    clue = read_marker(lane, "clue") if start is not None else None
    clue_ns = clue["at_ns"] if clue else None

    counts = Counter()
    operations = Counter()
    latency_ns = Counter()
    sizes = Counter()
    intervals = defaultdict(list)
    outcomes = defaultdict(Counter)
    samples = defaultdict(list)
    if start is not None:
        for row in read_rows(trial.requests):
            call_start, call_end = row["start_ns"], row["end_ns"]
            if not (start <= call_start <= end and call_end >= call_start):
                continue
            api = row["api"]
            operation = f"{api}:{row['operation']}"
            intervals[api].append((call_start, min(call_end, end)))
            tally = outcomes[operation]
            if call_end > end:
                tally["cutoff"] += 1
                continue

            duration = call_end - call_start
            counts[api] += 1
            operations[operation] += 1
            latency_ns[api] += duration
            sizes[api] += row.get("response_bytes", 0)
            outcome = row.get("outcome")
            if outcome is None:
                tally["unknown"] += 1
                if row.get("received_response") is False:
                    outcome = "client_error"
                elif row.get("received_response") is True:
                    outcome = ("notification" if row["operation"].startswith("notifications/")
                               else "response")
            tally[outcome] += 1
            if outcome in ("response", "response_error"):
                samples[operation].append(duration)

    latency_by_operation = {}
    for operation, tally in outcomes.items():
        observed = sorted(samples[operation])
        count = len(observed)
        latency_by_operation[operation] = {
            "sample_count": count,
            "p50_ms": observed[ceil(count * .50) - 1] / 1e6 if count else None,
            "p95_ms": observed[ceil(count * .95) - 1] / 1e6 if count else None,
            "error_count": tally["response_error"] + tally["client_error"],
            "censored_count": tally["timeout"] + tally["interrupted"] + tally["cutoff"],
            "notification_count": tally["notification"],
            "unknown_outcome_count": tally["unknown"],
        }
    return {
        "success": cutoff == "proof",
        "cutoff": cutoff,
        "seconds_to_proof_or_report": (end - start) / 1e9 if start is not None else None,
        "seconds_to_first_clue": ((clue_ns - start) / 1e9
                                  if clue_ns is not None and start <= clue_ns <= end else None),
        "calls": dict(counts),
        "calls_by_operation": dict(operations),
        "client_observed_seconds_by_api": {api: ns / 1e9 for api, ns in latency_ns.items()},
        "client_active_seconds_by_api": {api: union_seconds(spans)
                                         for api, spans in intervals.items()},
        "client_active_seconds": (union_seconds(span for spans in intervals.values() for span in spans)
                                  if start is not None else None),
        "request_latency_by_operation": latency_by_operation,
        "response_bytes_by_api": dict(sizes),
        "proof": str(proof_path) if proof_path.exists() else None,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("start", "clue", "stop", "report"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.operation == "report":
        now = time.perf_counter_ns()
        print(json.dumps({name: summarize(Trial(args.path / name), now)
                          for name in ("sql", "mcp")}, indent=2))
    else:
        Trial(args.path).stamp(args.operation)

