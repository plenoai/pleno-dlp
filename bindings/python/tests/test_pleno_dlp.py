import pathlib

import pytest

import pleno_dlp

# Split so the repository's own pre-commit scan does not flag the fixture.
HOOK = "/".join(["https://hooks.slack.com/services", "T024BE7LD", "B024BE7LD", "abcdefghijklmnopqrstuvwx"])


def test_version():
    assert pleno_dlp.api_version() == "1.1.0"


def test_scan_bytes_redacts_by_default():
    (f,) = pleno_dlp.scan_bytes("hook=" + HOOK)
    assert f.detector == "SlackWebhook"
    assert f.raw == "" and HOOK not in f.redacted
    assert not f.verified and f.verdict == "unverified"


def test_scan_bytes_include_raw_and_filter():
    (f,) = pleno_dlp.scan_bytes(HOOK.encode(), include_raw=True, detectors=["SlackWebhook"])
    assert f.raw == HOOK
    assert pleno_dlp.scan_bytes(HOOK, detectors=["AWS"]) == []


def test_scan_paths(tmp_path: pathlib.Path):
    p = tmp_path / "a.env"
    p.write_text("x=1\nhook=" + HOOK + "\n")
    (f,) = pleno_dlp.scan_paths(tmp_path)
    assert f.path == str(p) and f.line == 2


def test_errors():
    with pytest.raises(pleno_dlp.PlenoDLPError) as e:
        pleno_dlp.verify("NoSuch", "x")
    assert e.value.code == "unknown_detector"
    with pytest.raises(pleno_dlp.PlenoDLPError) as e:
        pleno_dlp.revoke("GitHub", "x")
    assert e.value.code == "not_confirmed"
    r = pleno_dlp.revoke("GitHub", "x", dry_run=True)
    assert r.dry_run and not r.revoked


def test_detectors():
    ds = {d.name: d for d in pleno_dlp.detectors()}
    assert ds["GitHub"].can_verify and ds["GitHub"].can_revoke
