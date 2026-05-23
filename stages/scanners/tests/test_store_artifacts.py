from scanners.findings.store import TargetStore
from scanners.models import Target


def test_write_artifacts_persists_stdout_as_output_json(tmp_path):
    store = TargetStore(tmp_path, Target("nginx:1.12", name="nginx"))
    store.write_artifacts("syft", stdout=b'{"a":1}')
    assert (tmp_path / "nginx" / "syft" / "output.json").read_bytes() == b'{"a":1}'


def test_write_artifacts_skips_empty_stdout(tmp_path):
    store = TargetStore(tmp_path, Target("x:1", name="x"))
    store.write_artifacts("trivy", stdout=b"")
    assert not (tmp_path / "x" / "trivy" / "output.json").exists()


def test_write_artifacts_failure_drops_forensics(tmp_path):
    store = TargetStore(tmp_path, Target("nginx:1.12", name="nginx"))
    store.write_artifacts("grype", stderr=b"boom\nbacktrace",
                          cmd=["docker", "run", "--rm", "anchore/grype:latest"],
                          exit_code=137, failed=True)
    d = tmp_path / "nginx" / "grype"
    assert (d / "error.log").read_bytes() == b"boom\nbacktrace"
    assert "anchore/grype:latest" in (d / "cmd.log").read_text()
    assert (d / "exit_code").read_text().strip() == "137"


def test_write_artifacts_ok_does_not_drop_forensics(tmp_path):
    store = TargetStore(tmp_path, Target("x:1", name="x"))
    store.write_artifacts("syft", stdout=b'{"a":1}', stderr=b"warn",
                          cmd=["docker", "run"], exit_code=0, failed=False)
    d = tmp_path / "x" / "syft"
    assert (d / "output.json").read_bytes() == b'{"a":1}'
    assert not (d / "error.log").exists()
    assert not (d / "cmd.log").exists()
    assert not (d / "exit_code").exists()
