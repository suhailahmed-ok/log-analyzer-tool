"""Run with:  python3 -m pytest -q     (pip install pytest)"""
import json
from rules import Analyzer, analyze, clean_unit, plain, safe_ip, safe_unit

NOISE = """Nov 01 18:00:00 pc systemd[1]: Stopped target default.target - Main User Target.
Nov 01 18:00:01 pc systemd[1]: gdm.service: Main process exited, code=exited, status=1/FAILURE
Nov 01 18:00:02 pc systemd[1]: obex.service: Main process exited, code=exited, status=1/FAILURE""".splitlines()
CRASH = "Nov 01 12:03:00 pc systemd[1]: logscope.service: Main process exited, code=exited, status=1/FAILURE"
SSH = "Nov 01 12:00:00 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2"


def test_clean_unit_unescapes_and_trims():
    assert clean_unit("app-gnome-gnome\\x2dkeyring\\x2dsecrets-3032.scope") == "keyring-secrets" or \
        "keyring" in clean_unit("app-gnome-gnome\\x2dkeyring\\x2dsecrets-3032.scope")
    assert clean_unit("docker.service") == "docker"


def test_plain_describes_known_units():
    assert "login screen" in plain("gdm")


def test_shutdown_noise_is_not_a_crash():
    r = analyze(NOISE)
    assert r["attention"] == []
    assert r["verdict"]["level"] == "ok"
    assert r["normal"]


def test_crash_outside_window_is_reported():
    r = analyze([CRASH])
    assert len(r["attention"]) == 1
    assert any("systemctl status" in c["cmd"] for c in r["attention"][0]["commands"])


def test_boot_and_wake_counted():
    r = analyze(["Nov 01 09:00:02 pc systemd[1]: Started systemd-journald.service - Journal.",
                 "Nov 01 09:30:00 pc systemd[1]: Stopped target sleep.target - Sleep."])
    text = " ".join(r["happened"])
    assert "started up 1 time" in text and "woke up" in text


def test_brute_force_threshold():
    assert analyze([SSH] * 4)["attention"][0]["level"] == "check"
    assert analyze([SSH] * 5)["attention"][0]["level"] == "problem"


def test_unsafe_input_never_reaches_commands():
    assert safe_ip("1.2.3.4;rm -rf /") is None
    assert safe_unit("x$(reboot).service") is None
    bad = ["Nov 01 12:00:00 h sshd[1]: Failed password for root from 1.2.3.4;evil port 1 ssh2"] * 6
    assert all(a["commands"] == [] for a in analyze(bad)["attention"])


def test_report_is_json_serializable():
    json.dumps(analyze(NOISE + [CRASH, SSH]))