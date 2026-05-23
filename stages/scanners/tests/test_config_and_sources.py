import pytest

from scanners.config import Config, ConfigError
from scanners.sources import get_source


def test_example_config_loads():
    cfg = Config.load("config/config.example.yaml")
    assert cfg.workers.count == 4 and cfg.queue.backend == "sqlite"
    assert cfg.runtime.hardened is True and cfg.source.type == "csv"
    # paths resolve relative to the repo root (config/'s parent)
    assert cfg.out_dir.name == "out"


def test_unknown_section_rejected(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("nope:\n  x: 1\n")
    with pytest.raises(ConfigError):
        Config.load(p)


def test_unknown_key_rejected(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("workers:\n  count: 2\n  bogus: 1\n")
    with pytest.raises(ConfigError):
        Config.load(p)


def test_csv_source(tmp_path):
    inv = tmp_path / "inv.csv"
    inv.write_text("Category,Container,Image,Port,IP,Type\n"
                   "DB,redis50,redis:5.0,127.0.0.1:6381:6379,172.31.1.33,Outdated\n"
                   "Web,dvwa,vulnerables/web-dvwa,127.0.0.1:8005:80,172.30.9.1,Vulnerable\n"
                   ",skipme,,-,-,-\n")
    cp = tmp_path / "config.yaml"
    cp.write_text(f"source:\n  type: csv\n  path: {inv}\n")
    targets = get_source(Config.load(cp)).targets()
    assert {t.image for t in targets} == {"redis:5.0", "vulnerables/web-dvwa:latest"}
    redis = next(t for t in targets if t.name == "redis50")
    assert redis.ip == "172.31.1.33" and redis.meta["Category"] == "DB"


def test_jsonl_ditector_source(tmp_path):
    j = tmp_path / "r.jsonl"
    j.write_text('{"repository_namespace":"library","repository_name":"nginx","tag_name":"1.12","weights":900}\n'
                 '{"repository_namespace":"bitnami","repository_name":"redis","tag_name":"6.0","weights":300}\n')
    cp = tmp_path / "config.yaml"
    cp.write_text(f"source:\n  type: jsonl\n  path: {j}\n")
    targets = get_source(Config.load(cp)).targets()
    assert [t.image for t in targets] == ["nginx:1.12", "bitnami/redis:6.0"]   # ordered by weight
    assert targets[0].weight == 900.0
