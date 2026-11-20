import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from measure import Rpc, Trial, summarize
import memory


def write_rows(path, rows):
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf8")


class TrialFixture(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.run = Path(temp.name)
        self.lane = self.run / "sql"
        self.lane.mkdir()
        self.write_json(self.run / "preflight.json", {
            "lanes": {"sql": {}}, "sample_sha256": "synthetic",
        })
        self.trial = Trial(self.lane)

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value), encoding="utf8")

    def marker(self, name, milliseconds, **fields):
        self.write_json(self.lane / f"{name}.json", {
            "at_ns": milliseconds * 1_000_000, **fields,
        })


class RequestMetricsTests(TrialFixture):
    def test_reports_response_percentiles_errors_and_overlapped_activity(self):
        self.marker("start", 100)
        self.marker("proof", 200, success=True)
        self.marker("stop", 210)
        self.marker("clue", 120)

        def row(start, end, outcome, api="sql_stdio", operation="query"):
            return {"api": api, "operation": operation, "outcome": outcome,
                    "start_ns": start * 1_000_000, "end_ns": end * 1_000_000,
                    "response_bytes": 10}

        write_rows(self.trial.requests, [
            row(130, 170, "response_error"),
            row(95, 105, "response"),  # Exclude preflight.
            row(100, 110, "response"),
            row(108, 128, "response"),
            row(115, 145, "response", api="other"),
            row(178, 179, "client_error"),
            row(179, 180, "notification", operation="notice"),
            row(181, 190, "timeout"),
            row(195, 205, "response"),  # Censored by proof.
            row(200, 203, "response"),  # Starts at cutoff, completed afterward.
            row(201, 205, "response"),  # Exclude post-proof requests.
        ])

        report = summarize(self.trial)
        self.assertTrue(report["success"])
        self.assertEqual(report["cutoff"], "proof")
        self.assertEqual(report["seconds_to_first_clue"], .020)
        self.assertEqual(report["calls"], {"sql_stdio": 6, "other": 1})
        self.assertEqual(report["response_bytes_by_api"], {"sql_stdio": 60, "other": 10})
        self.assertAlmostEqual(report["client_observed_seconds_by_api"]["sql_stdio"], .081)
        self.assertEqual(report["client_active_seconds"], .086)
        self.assertEqual(report["client_active_seconds_by_api"], {
            "sql_stdio": .084, "other": .030,
        })
        self.assertEqual(report["request_latency_by_operation"]["sql_stdio:query"], {
            "sample_count": 3, "p50_ms": 20.0, "p95_ms": 40.0,
            "error_count": 2, "censored_count": 3, "notification_count": 0,
            "unknown_outcome_count": 0,
        })
        self.assertEqual(report["request_latency_by_operation"]["sql_stdio:notice"], {
            "sample_count": 0, "p50_ms": None, "p95_ms": None,
            "error_count": 0, "censored_count": 0, "notification_count": 1,
            "unknown_outcome_count": 0,
        })

    def test_old_requests_and_incomplete_log_tail_have_explicit_semantics(self):
        self.marker("start", 100)
        self.marker("stop", 200)
        self.marker("proof", 140, success=False)
        self.marker("clue", 250)
        write_rows(self.trial.requests, [
            {"api": "sql_cli", "operation": "query", "start_ns": 100_000_000,
             "end_ns": 116_000_000, "received_response": True},
            {"api": "sql_cli", "operation": "query", "start_ns": 140_000_000,
             "end_ns": 180_000_000, "received_response": False},
            {"api": "sql_stdio", "operation": "notifications/initialized",
             "start_ns": 125_000_000, "end_ns": 130_000_000,
             "received_response": True},
        ])
        with self.trial.requests.open("a", encoding="utf8") as stream:
            stream.write('{"api":')

        report = summarize(self.trial)
        self.assertFalse(report["success"])
        self.assertEqual(report["cutoff"], "stop")
        self.assertIsNone(report["seconds_to_first_clue"])
        self.assertEqual(report["request_latency_by_operation"]["sql_cli:query"], {
            "sample_count": 1, "p50_ms": 16.0, "p95_ms": 16.0,
            "error_count": 1, "censored_count": 0, "notification_count": 0,
            "unknown_outcome_count": 2,
        })
        self.assertEqual(report["request_latency_by_operation"][
            "sql_stdio:notifications/initialized"]["notification_count"], 1)

    def test_missing_start_has_unknown_time_and_live_cut_has_zero_activity(self):
        self.assertEqual(summarize(self.trial)["cutoff"], "not_started")
        self.assertIsNone(summarize(self.trial)["seconds_to_proof_or_report"])
        self.assertIsNone(summarize(self.trial)["client_active_seconds"])

        self.marker("start", 100)
        with patch("measure.time.perf_counter_ns", return_value=120_000_000):
            report = summarize(self.trial)
        self.assertEqual(report["cutoff"], "report_time")
        self.assertEqual(report["seconds_to_proof_or_report"], .020)
        self.assertEqual(report["client_active_seconds"], 0.0)

    def test_live_cutoff_can_precede_a_concurrent_start(self):
        self.marker("start", 101)
        report = summarize(self.trial, now_ns=100_000_000)
        self.assertEqual(report["cutoff"], "not_started")
        self.assertIsNone(report["seconds_to_proof_or_report"])

    def test_marker_publication_hides_partial_contents_and_preserves_exclusivity(self):
        self.marker("start", 100)
        dump = json.dump

        def inspect_before_publication(data, stream, **kwargs):
            stream.write("{")
            stream.flush()
            self.assertEqual(summarize(self.trial)["cutoff"], "report_time")
            stream.seek(0)
            dump(data, stream, **kwargs)

        with patch("measure.json.dump", side_effect=inspect_before_publication):
            self.trial.stamp("stop")
        published = (self.lane / "stop.json").read_bytes()
        with self.assertRaises(FileExistsError):
            self.trial.stamp("stop")
        self.assertEqual((self.lane / "stop.json").read_bytes(), published)
        self.assertEqual(summarize(self.trial)["cutoff"], "stop")

    def test_sql_cli_success_with_null_error_is_a_response(self):
        reply = {"ok": True, "error": None, "rows": []}
        self.assertIs(self.trial.call("sql_cli", "query", lambda: reply), reply)
        row = json.loads(self.trial.requests.read_text(encoding="utf8"))
        self.assertEqual(row["outcome"], "response")

    def test_records_protocol_error_notification_timeout_and_client_failure(self):
        rpc = Rpc("sql_stdio", self.trial, lambda message: {
            "error": {"code": -1}
        } if "id" in message else None)
        self.assertIn("error", rpc.request("tools/list"))
        self.assertIsNone(rpc.request("notifications/initialized", notify=True))

        tool = Rpc("sql_stdio", self.trial,
                   lambda _: {"result": {"isError": True}})
        self.assertEqual(tool.tool("synthetic"), {"isError": True})

        def timeout():
            raise TimeoutError

        def parse_failure():
            raise ValueError

        for invoke, error in ((timeout, TimeoutError), (parse_failure, ValueError)):
            with self.assertRaises(error):
                self.trial.call("test", "synthetic", invoke)

        rows = [json.loads(line) for line in self.trial.requests.read_text(
            encoding="utf8").splitlines()]
        self.assertEqual([row["outcome"] for row in rows], [
            "response_error", "notification", "response_error", "timeout", "client_error",
        ])
        self.assertEqual([row["received_response"] for row in rows], [
            True, True, True, False, False,
        ])


class MemoryMetricsTests(TrialFixture):
    def test_registration_reader_keeps_offset_and_retries_partial_row(self):
        stream = io.StringIO('{"role":"host","pid":10}\n{"role":"analyzer","pid":')
        self.assertEqual(list(memory.read_registrations(stream)), [
            {"role": "host", "pid": 10},
        ])
        partial = stream.tell()
        self.assertEqual(list(memory.read_registrations(stream)), [])
        self.assertEqual(stream.tell(), partial)
        stream.seek(0, io.SEEK_END)
        stream.write("11}\n")
        stream.seek(partial)
        self.assertEqual(list(memory.read_registrations(stream)), [
            {"role": "analyzer", "pid": 11},
        ])
        self.assertEqual(list(memory.read_registrations(stream)), [])

    def test_memory_report_shows_coverage_and_only_sums_same_instant(self):
        self.marker("start", 100)
        self.marker("stop", 200)
        self.marker("proof", 110, success=False)
        self.trial.track("host", 10)
        self.trial.track("analyzer", 11)
        self.trial.track("missing", 12)

        def row(at, role, pid, working, private):
            return {"lane": "sql", "at_ns": at * 1_000_000, "role": role,
                    "pid": pid, "working": working, "private": private}

        write_rows(self.run / "memory.jsonl", [
            row(90, "host", 10, 1000, 1000),
            row(120, "host", 10, 30, 10),
            row(120, "analyzer", 11, 70, 100),
            row(150, "host", 10, 60, 20),
            row(150, "analyzer", 11, 20, 10),
            row(205, "missing", 12, 1000, 1000),
        ])
        report = memory.summarize(self.run)
        self.assertEqual(report["sql"]["cutoff"], "stop")
        self.assertEqual(report["sql"]["samples"], 2)
        self.assertEqual(report["sql"]["peak_combined_working"], 100)
        self.assertEqual(report["sql"]["peak_combined_private"], 110)
        self.assertEqual(report["sql"]["peak_by_role"]["host"], {
            "working": 60, "private": 20,
        })
        self.assertEqual(report["sql"]["unsampled_processes"], [
            {"role": "missing", "pid": 12},
        ])
        self.assertEqual(report["mcp"]["cutoff"], "not_started")
        self.assertIsNone(report["mcp"]["peak_combined_private"])

    def test_missing_memory_log_and_zero_measurement_are_distinct(self):
        self.marker("start", 100)
        self.marker("stop", 200)
        self.trial.track("host", 10)

        missing = memory.summarize(self.run)["sql"]
        self.assertFalse(missing["memory_log_present"])
        self.assertEqual(missing["samples"], 0)
        self.assertIsNone(missing["peak_combined_working"])
        self.assertEqual(missing["unsampled_processes"], [{"role": "host", "pid": 10}])

        write_rows(self.run / "memory.jsonl", [{
            "lane": "sql", "at_ns": 150_000_000, "role": "host", "pid": 10,
            "working": 0, "private": 0,
        }])
        measured = memory.summarize(self.run)["sql"]
        self.assertTrue(measured["memory_log_present"])
        self.assertEqual(measured["samples"], 1)
        self.assertEqual(measured["peak_combined_working"], 0)
        self.assertEqual(measured["unsampled_processes"], [])


if __name__ == "__main__":
    unittest.main()
