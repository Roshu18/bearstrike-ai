import sqlite3
import time
import unittest

from core.control_plane import (
    DB_PATH,
    ACTIVE_JOB_STALE_SECONDS,
    append_run_event,
    cache_stats,
    dedupe_stats,
    ensure_db,
    find_active_job_by_fingerprint,
    get_cached_response,
    purge_old_scan_data,
    record_run_job,
    request_fingerprint,
    save_install_state,
    score_endpoint,
    store_research_findings,
    upsert_request_cache,
)


class ControlPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        ensure_db()

    def test_fingerprint_is_deterministic(self) -> None:
        first = request_fingerprint(
            tool_name="nmap",
            target="https://EXAMPLE.com/",
            params={"timeout_seconds": 30},
            mode="low_noise",
            scope_tag="smoke",
        )
        second = request_fingerprint(
            tool_name="nmap",
            target="example.com",
            params={"timeout_seconds": 30},
            mode="low_noise",
            scope_tag="smoke",
        )
        self.assertEqual(first, second)

    def test_endpoint_scoring_high_risk(self) -> None:
        store_research_findings(
            [
                {
                    "source": "unit-test",
                    "vulnerability_class": "idor-bola",
                    "endpoint_pattern": "/api/user",
                    "payload_snippet": "swap ids",
                    "method": "GET",
                    "exploitation_notes": "check auth",
                    "confidence": 0.9,
                    "discovered_at": time.time(),
                }
            ],
            replace_window_days=1,
        )
        result = score_endpoint(
            target="hackerone.com",
            endpoint="/api/user?id=1234",
            method="GET",
            context="hackerone",
        )
        self.assertGreaterEqual(int(result["score"]), 8)
        self.assertEqual(result["priority_band"], "high")

    def test_cache_roundtrip(self) -> None:
        fingerprint = request_fingerprint(
            tool_name="whatweb",
            target="example.com",
            params={"timeout_seconds": 10},
            mode="balanced",
            scope_tag="unit",
        )
        upsert_request_cache(
            fingerprint=fingerprint,
            tool="whatweb",
            target="example.com",
            params={"timeout_seconds": 10},
            mode="balanced",
            scope_tag="unit",
            status="success",
            summary="example summary",
            response_ref="",
            response_excerpt="example excerpt",
            ttl_profile={"balanced": 600},
        )
        cached = get_cached_response(fingerprint)
        self.assertIsNotNone(cached)
        self.assertEqual(cached.get("status"), "success")

    def test_dedupe_stats_tracks_collapsed_jobs(self) -> None:
        stamp = int(time.time() * 1000)
        base_job = f"unit-base-{stamp}"
        dedupe_job = f"unit-dedupe-{stamp}"

        fp = request_fingerprint(
            tool_name="httpx",
            target="example.com",
            params={"timeout_seconds": 8},
            mode="low_noise",
            scope_tag="unit",
        )

        record_run_job(
            job_id=base_job,
            source="unit",
            tool_name="httpx",
            target="example.com",
            params={"timeout_seconds": 8},
            fingerprint=fp,
            status="queued",
            deduped_to_job_id="",
        )
        record_run_job(
            job_id=dedupe_job,
            source="unit",
            tool_name="httpx",
            target="example.com",
            params={"timeout_seconds": 8},
            fingerprint=fp,
            status="deduped",
            deduped_to_job_id=base_job,
        )

        stats = dedupe_stats()
        self.assertGreaterEqual(int(stats.get("deduped_jobs", 0)), 1)
        self.assertGreaterEqual(int(stats.get("total_jobs", 0)), 2)
        self.assertIn("cache_hit_jobs", stats)
        self.assertIn("total_entries", cache_stats())

    def test_stale_active_job_is_not_deduped_forever(self) -> None:
        stamp = int(time.time() * 1000)
        stale_job = f"unit-stale-{stamp}"
        fp = request_fingerprint(
            tool_name="subfinder",
            target="example.com",
            params={"timeout_seconds": 20},
            mode="low_noise",
            scope_tag="unit-stale",
        )

        record_run_job(
            job_id=stale_job,
            source="unit",
            tool_name="subfinder",
            target="example.com",
            params={"timeout_seconds": 20},
            fingerprint=fp,
            status="queued",
            deduped_to_job_id="",
        )

        stale_created_at = time.time() - (ACTIVE_JOB_STALE_SECONDS + 120)
        conn = sqlite3.connect(str(DB_PATH))
        try:
            conn.execute(
                "UPDATE run_jobs SET created_at = ? WHERE job_id = ?",
                [stale_created_at, stale_job],
            )
            conn.commit()
        finally:
            conn.close()

        active = find_active_job_by_fingerprint(fp)
        self.assertIsNone(active)

        conn = sqlite3.connect(str(DB_PATH))
        try:
            row = conn.execute(
                "SELECT status, error FROM run_jobs WHERE job_id = ? LIMIT 1",
                [stale_job],
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(str(row[0]).lower(), "failed")
        self.assertIn("stale active job auto-closed", str(row[1]))

    def test_purge_old_scan_data_deletes_old_rows(self) -> None:
        stamp = int(time.time() * 1000)
        old_job = f"unit-old-{stamp}"
        fp = request_fingerprint(
            tool_name="nmap",
            target="example.com",
            params={"timeout_seconds": 10},
            mode="low_noise",
            scope_tag="unit-purge",
        )

        record_run_job(
            job_id=old_job,
            source="unit",
            tool_name="nmap",
            target="example.com",
            params={"timeout_seconds": 10},
            fingerprint=fp,
            status="success",
            deduped_to_job_id="",
        )
        append_run_event(old_job, "finished", "unit old event")

        old_created_at = time.time() - (9 * 86400)
        conn = sqlite3.connect(str(DB_PATH))
        try:
            conn.execute("UPDATE run_jobs SET created_at = ? WHERE job_id = ?", [old_created_at, old_job])
            conn.execute("UPDATE run_events SET created_at = ? WHERE job_id = ?", [old_created_at, old_job])
            conn.commit()
        finally:
            conn.close()

        result = purge_old_scan_data(older_than_days=7, include_research=False, vacuum=False)
        self.assertGreaterEqual(int((result.get("deleted") or {}).get("run_jobs", 0)), 1)
        self.assertGreaterEqual(int((result.get("deleted") or {}).get("run_events", 0)), 1)

    def test_purge_clear_all_wipes_install_state(self) -> None:
        save_install_state(
            tool_name="unit-clear-all-tool",
            detected_status="installed",
            user_state="user_managed",
            install_result="installed",
            install_attempted=True,
        )
        result = purge_old_scan_data(older_than_days=7, include_research=True, vacuum=False, clear_all=True)
        self.assertTrue(bool(result.get("clear_all", False)))
        self.assertGreaterEqual(int((result.get("deleted") or {}).get("tool_install_state", 0)), 1)


if __name__ == "__main__":
    unittest.main()
