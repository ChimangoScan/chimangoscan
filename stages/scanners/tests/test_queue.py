from scanners.jobqueue.sqlite_queue import SqliteQueue
from scanners.models import Target


def _q(tmp_path):
    return SqliteQueue(tmp_path / "q.db")


def test_seed_is_idempotent(tmp_path):
    q = _q(tmp_path)
    ts = [Target("nginx:1.12"), Target("redis:5.0")]
    assert q.seed(ts) == 2
    assert q.seed(ts) == 0                         # same images -> nothing new
    assert q.seed(ts + [Target("httpd:2.4")]) == 1
    assert q.stats()["total"] == 3


def test_claim_orders_by_weight_and_is_exclusive(tmp_path):
    q = _q(tmp_path)
    q.seed([Target("a:1", weight=1), Target("b:1", weight=9), Target("c:1", weight=5)])
    assert q.claim("w1").target.image == "b:1"      # highest weight first
    assert q.claim("w2").target.image == "c:1"
    j = q.claim("w3")
    assert j.target.image == "a:1"
    assert q.claim("w4") is None                    # nothing left pending
    st = q.stats()
    assert st["running"] == 3 and st["pending"] == 0


def test_complete_stores_report(tmp_path):
    q = _q(tmp_path)
    q.seed([Target("nginx:1.12")])
    j = q.claim("w1")
    q.complete(j.id, "w1", {"target": {"image": "nginx:1.12"}, "findings": [{"id": "CVE-1"}]})
    assert q.stats()["done"] == 1
    reports = list(q.iter_reports())
    assert len(reports) == 1 and reports[0]["findings"][0]["id"] == "CVE-1"


def test_fail_retries_then_gives_up(tmp_path):
    q = _q(tmp_path)
    q.seed([Target("x:1")])
    for _ in range(3):
        j = q.claim("w")
        assert j is not None
        q.fail(j.id, "w", "boom", max_attempts=3)
    # third failure with attempts==3 marks it failed; nothing claimable now
    assert q.claim("w") is None
    assert q.stats()["failed"] == 1


def test_reset_stale_reclaims(tmp_path):
    q = _q(tmp_path)
    q.seed([Target("x:1")])
    q.claim("w")
    assert q.reset_stale(0) == 1                    # everything running is "stale" at 0 minutes
    assert q.stats()["pending"] == 1


def test_skip_and_reset(tmp_path):
    q = _q(tmp_path)
    q.seed([Target("x:1"), Target("y:1")])
    a = q.claim("w"); q.skip(a.id, "w", "too big")
    b = q.claim("w"); q.fail(b.id, "w", "net", max_attempts=1)
    assert q.stats()["skipped"] == 1 and q.stats()["failed"] == 1
    assert q.reset(failed=True, skipped=True) == 2
    assert q.stats()["pending"] == 2
