"""LOGSCOPE rules: turn raw journalctl lines into plain English.

Used by the terminal tool (cli.py) and by the Flask app.
Nothing in here runs a command. It only reads text and explains it.
"""
import ipaddress
import json
import re
from collections import Counter, defaultdict
from datetime import datetime

# default journalctl line: "Nov 01 12:04:01 host unit[123]: message"
SHORT = re.compile(r"^(\w{3}\s+\d+\s[\d:]+)\s(\S+)\s([^:\[]+)(?:\[\d+\])?:\s(.*)$")
LIFECYCLE = re.compile(r"^(Started|Stopped)\s+(target\s+)?(\S+)")
HEX_ESC = re.compile(r"\\x([0-9a-fA-F]{2})")
UNIT_SUFFIX = re.compile(r"\.(service|scope|target|socket|timer|mount|slice|path|device|swap)$")
UNIT_OK = re.compile(r"^[A-Za-z0-9_.@:\-]+$")

# A "session closing" (logout, login-screen handoff, shutdown) makes many desktop
# helpers exit with errors. Errors within this many seconds of it are normal noise.
WINDOW_SECONDS = 20
SESSION_ENDERS = {"default", "graphical-session", "graphical", "multi-user"}

# (text to look for in the unit name, plain description, note if its failure is harmless)
KNOWN = [
    ("gdm", "the login screen", None),
    ("xdg-permission-store", "a desktop helper that remembers which permissions your apps were given", None),
    ("xdg-document-portal", "a desktop helper that lets sandboxed (Snap/Flatpak) apps open your files", None),
    ("xdg-desktop-portal", "a desktop helper that lets sandboxed apps use file pickers and screenshots", None),
    ("snapd-desktop-integration", "a helper that makes Snap apps match your desktop", None),
    ("obex", "the Bluetooth file-transfer helper", None),
    ("gnome-keyring", "the keyring that stores your saved passwords",
     "Usually harmless: it is often already running by the time this copy tries to start. "
     "Only worth a look if apps keep asking for your saved passwords again."),
    ("spice-vdagent", "a helper that only matters inside a virtual machine",
     "Harmless on a normal computer."),
    ("user-dirs-update", "a helper that creates your standard folders (Documents, Downloads...)",
     "Usually harmless. It tries again at the next login."),
    ("docker-desktop", "Docker Desktop", None),
    ("docker", "Docker", None),
    ("containerd", "the engine underneath Docker", None),
    ("networkmanager", "the service that manages Wi-Fi and network connections", None),
    ("bluetooth", "Bluetooth", None),
    ("cups", "the printing service", None),
    ("avahi", "the service that finds devices on your network", None),
    ("modemmanager", "the mobile-broadband service", None),
    ("wpa_supplicant", "the Wi-Fi security service", None),
    ("packagekit", "the software-update helper", None),
    ("snapd", "the Snap app manager", None),
    ("fprintd", "the fingerprint reader service", None),
    ("systemd-oomd", "the system's out-of-memory protector", None),
    ("ssh", "the SSH remote-login service", None),
]


# ----------------------------------------------------------------- parsing helpers
def parse(line):
    """Return (timestamp, message) from a journalctl line (plain text or -o json)."""
    line = line.rstrip("\n")
    if line.startswith("{"):
        try:
            d = json.loads(line)
            msg = d.get("MESSAGE", "")
            if not isinstance(msg, str):
                msg = str(msg)
            us = int(d.get("__REALTIME_TIMESTAMP", 0))
            ts = datetime.fromtimestamp(us / 1e6).strftime("%b %d %H:%M:%S") if us else ""
            return ts, msg
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
    m = SHORT.match(line)
    if m:
        return m.group(1), m.group(4)
    return "", line


def to_epoch(ts):
    """Seconds for a 'Nov 02 11:31:45' stamp (year is irrelevant, only differences are used)."""
    if not ts:
        return None
    try:
        dt = datetime.strptime("2000 " + " ".join(ts.split()), "%Y %b %d %H:%M:%S")
        return (dt - datetime(2000, 1, 1)).total_seconds()
    except ValueError:
        return None


def clean_unit(raw):
    """'app-gnome-gnome\\x2dkeyring\\x2dsecrets-3032.scope' -> 'gnome-keyring-secrets'."""
    s = HEX_ESC.sub(lambda m: chr(int(m.group(1), 16)), raw.strip().rstrip(".,]"))
    s = UNIT_SUFFIX.sub("", s)
    s = re.sub(r"^app-(?:gnome-)?", "", s)
    s = re.sub(r"-\d{2,}$", "", s)
    return s


def lookup(name):
    low = name.lower()
    for key, desc, note in KNOWN:
        if key in low:
            return key, desc, note
    return None


def plain(name):
    k = lookup(name)
    return f"{k[1]} ({k[0]})" if k else f"'{name}'"


def cap(s):
    return s[:1].upper() + s[1:]


def times(n, word):
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def short_time(ts):
    return ts.rsplit(":", 1)[0] if ts else "?"


def safe_ip(s):
    """Log text is untrusted: only real IP addresses may end up inside a command."""
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


def safe_unit(s):
    return s if UNIT_OK.match(s) else None


# ----------------------------------------------------------------- event patterns
RULES = [(re.compile(p), kind) for p, kind in [
    (r"Failed password for (?:invalid user )?(\S+) from (\S+)", "ssh_fail"),
    (r"Accepted (\w+) for (\S+) from (\S+)", "ssh_ok"),
    (r"^\s*(\S+)\s*: .*COMMAND=(.*)", "sudo"),
    (r"Failed to start (\S+)", "svc_fail"),
    (r"(\S+): Main process exited, code=(\w+), status=(\S+)", "svc_crash"),
    (r"Out of memory: Killed process (\d+) \((\S+)\)", "oom"),
    (r"No space left on device", "disk_full"),
    (r"segfault", "segfault"),
]]


def ev(ts, level, kind, text):
    return {"time": ts, "level": level, "kind": kind, "text": text}


# ----------------------------------------------------------------- the analyzer
class Analyzer:
    """Feed it journal lines one at a time; ask report() what happened."""

    def __init__(self, brute=5):
        self.brute = brute
        self.total = 0
        self.first_ts = self.last_ts = ""
        self.starts = self.stops = 0
        self.boots, self.shutdowns, self.wakes = [], [], []
        self.marker = None                      # epoch of the last "session closing" signal
        self.ssh_fail = defaultdict(lambda: {"n": 0, "users": set()})
        self.ssh_ok = []
        self.sudo = []
        self.normal = Counter()                 # plain label -> count (harmless noise)
        self.normal_note = {}
        self.crash = {}                         # raw unit -> count (real crashes)
        self.start_fail = Counter()             # plain label -> count
        self.oom = []
        self.disk_full = 0
        self.segfault = 0

    # -- one line in, at most one event out
    def feed(self, raw):
        ts, msg = parse(raw)
        if not msg.strip():
            return None
        self.total += 1
        if ts:
            self.first_ts = self.first_ts or ts
            self.last_ts = ts
        ep = to_epoch(ts)
        in_window = (self.marker is not None and ep is not None
                     and 0 <= ep - self.marker <= WINDOW_SECONDS)

        m = LIFECYCLE.match(msg)
        if m:
            return self._lifecycle(ts, ep, m.group(1), bool(m.group(2)), m.group(3))

        for pat, kind in RULES:
            m = pat.search(msg)
            if m:
                return self._event(kind, m.groups(), ts, in_window)
        return None

    def _lifecycle(self, ts, ep, verb, has_target_word, raw_name):
        is_target = has_target_word or raw_name.endswith(".target")
        name = clean_unit(raw_name)
        low = name.lower()
        if verb == "Started":
            self.starts += 1
            if not is_target and low == "systemd-journald":
                self.boots.append(ts)
                return ev(ts, "info", "boot", "Your computer started up.")
            if low.startswith(("plymouth-poweroff", "plymouth-reboot", "plymouth-halt")):
                word = "restarted" if "reboot" in low else "shut down"
                self.shutdowns.append((ts, word))
                return ev(ts, "info", "shutdown", f"Your computer {word}.")
            return ev(ts, "hidden", "start", f"Started {name}")
        self.stops += 1
        if is_target and low == "sleep":
            self.wakes.append(ts)
            return ev(ts, "info", "wake", "Your computer woke up from sleep.")
        if is_target and (low in SESSION_ENDERS or low.startswith("gnome-session")):
            self.marker = ep
        return ev(ts, "hidden", "stop", f"Stopped {name}")

    def _event(self, kind, g, ts, in_window):
        if kind == "ssh_fail":
            user, ip = g
            self.ssh_fail[ip]["n"] += 1
            self.ssh_fail[ip]["users"].add(user)
            return ev(ts, "check", kind,
                      f"Someone tried to log in over SSH as '{user}' with a wrong password (from {ip}).")
        if kind == "ssh_ok":
            how, user, ip = g
            self.ssh_ok.append((ts, user, ip))
            return ev(ts, "info", kind, f"{user} logged in over SSH from {ip} (using {how}).")
        if kind == "sudo":
            user, cmd = g[0], g[1].strip().rstrip("]")
            self.sudo.append((ts, user, cmd))
            return ev(ts, "info", kind, f"{user} used admin rights (sudo) to run: {cmd}")
        if kind == "svc_fail":
            name = clean_unit(g[0])
            label = plain(name)
            k = lookup(name)
            if in_window or (k and k[2]):
                self.normal[label] += 1
                if k and k[2]:
                    self.normal_note[label] = k[2]
                return ev(ts, "normal", kind, f"{cap(label)} could not start (harmless).")
            self.start_fail[label] += 1
            return ev(ts, "check", kind, f"{cap(label)} could not start.")
        if kind == "svc_crash":
            raw, code, status = g
            if status.startswith("0/") or (code == "killed" and status.startswith(("15/", "SIGTERM"))):
                return None                      # a normal stop, not a problem
            name = clean_unit(raw)
            label = plain(name)
            if in_window:
                self.normal[label] += 1
                return ev(ts, "normal", kind,
                          f"{cap(label)} stopped with an error while the desktop session was closing (normal).")
            self.crash[raw] = self.crash.get(raw, 0) + 1
            return ev(ts, "check", kind,
                      f"{cap(label)} stopped unexpectedly (exit status {status}).")
        if kind == "oom":
            pid, prog = g
            self.oom.append(prog)
            return ev(ts, "problem", kind,
                      f"Your computer ran out of memory, so the system force-closed '{prog}'.")
        if kind == "disk_full":
            self.disk_full += 1
            return ev(ts, "problem", kind, "Your disk is full. Programs can't save files.")
        if kind == "segfault":
            self.segfault += 1
            return ev(ts, "check", kind, "A program crashed (a 'segmentation fault').")
        return None

    # -- the final plain-English report (JSON friendly)
    def report(self):
        happened = []
        if self.boots:
            when = ", ".join(short_time(t) for t in self.boots[:5])
            happened.append(f"Your computer started up {times(len(self.boots), 'time')} ({when}).")
        if self.shutdowns:
            happened.append(f"It was shut down or restarted {times(len(self.shutdowns), 'time')}.")
        if self.wakes:
            happened.append(f"It woke up from sleep {times(len(self.wakes), 'time')}.")
        if self.ssh_ok:
            who = ", ".join(sorted({f"{u} from {ip}" for _, u, ip in self.ssh_ok})[:3])
            happened.append(f"{times(len(self.ssh_ok), 'remote (SSH) login')}: {who}.")
        if self.sudo:
            routine = [s for s in self.sudo if "update-notifier" in s[2]]
            other = [s for s in self.sudo if s not in routine]
            if routine:
                happened.append(f"The system ran {times(len(routine), 'routine update check')} "
                                "with admin rights (normal).")
            for ts, user, cmd in other[:5]:
                happened.append(f"{user} used admin rights (sudo) to run: {cmd} ({short_time(ts)})")
        if not happened:
            happened.append("Not much happened in this time window.")

        normal = [{"title": f"{cap(label)}: {times(n, 'time')}",
                   "why": self.normal_note.get(label)} for label, n in self.normal.most_common()]

        attention = []
        for ip, d in sorted(self.ssh_fail.items(), key=lambda kv: -kv[1]["n"]):
            n, users = d["n"], ", ".join(sorted(d["users"])[:5])
            level = "problem" if n >= self.brute else "check"
            item = {"level": level,
                    "title": f"{times(n, 'failed SSH login attempt')} from {ip}",
                    "explain": (f"Someone (often an automated bot) tried to guess the password for: {users}. "
                                "This is common on any computer that is reachable from the internet. "
                                "If it keeps happening, block that address and switch to SSH keys."),
                    "commands": []}
            if safe_ip(ip):
                ip = safe_ip(ip)
                item["commands"] = [
                    c(f"sudo journalctl -u ssh --grep {ip} --since today --no-pager | tail -20",
                      "Shows what that address tried. (On some systems the service is called 'sshd', not 'ssh'.)"),
                    c("sudo apt install fail2ban",
                      "Installs a tool that automatically blocks addresses that keep failing."),
                    c(f"sudo ufw deny from {ip}",
                      "Blocks that address. Make sure it is not your own first."),
                    c("grep -E '^(PasswordAuthentication|PermitRootLogin)' /etc/ssh/sshd_config",
                      "Shows whether password logins are allowed. Safer: turn them off and use SSH keys, "
                      "but set a key up first so you can't lock yourself out."),
                ]
            attention.append(item)

        for raw, n in sorted(self.crash.items(), key=lambda kv: -kv[1]):
            label = plain(clean_unit(raw))
            item = {"level": "problem" if n >= 3 else "check",
                    "title": f"{cap(label)} stopped unexpectedly {times(n, 'time')}",
                    "explain": ("A background program quit with an error at a time when you were not "
                                "logging in, logging out or shutting down. "
                                "The commands below usually show the reason."),
                    "commands": []}
            u = safe_unit(raw)
            if u:
                item["commands"] = [
                    c(f"systemctl status {u} --no-pager",
                      "Shows whether it is running right now, plus its last few messages."),
                    c(f"journalctl -u {u} -n 50 --no-pager",
                      "Shows the last 50 messages it wrote. The reason it stopped is usually in here."),
                    c(f"journalctl -u {u} -p err -b --no-pager",
                      "Shows only its error messages since you last turned the computer on."),
                    c(f"sudo systemctl restart {u}",
                      "Starts it again. Try this after you understand the cause."),
                ]
            attention.append(item)

        for label, n in self.start_fail.most_common():
            attention.append({
                "level": "check",
                "title": f"{cap(label)} could not start ({times(n, 'time')})",
                "explain": "It tried to start and failed. These commands show which services are failing and why.",
                "commands": [
                    c("systemctl --failed", "Lists every service that is currently in a failed state."),
                    c("journalctl -xe --no-pager | tail -40",
                      "Shows the latest errors with extra explanations from systemd."),
                ]})

        if self.oom:
            attention.append({
                "level": "problem",
                "title": f"The computer ran out of memory ({times(len(self.oom), 'time')})",
                "explain": ("When memory runs out, Linux force-closes a program to survive. "
                            f"Closed this time: {', '.join(sorted(set(self.oom)))}."),
                "commands": [
                    c("free -h", "Shows how much memory is free right now."),
                    c("ps aux --sort=-%mem | head -10", "Lists the 10 programs using the most memory."),
                    c("dmesg -T | grep -i 'killed process'", "Shows what the system closed, and when."),
                    c("docker stats --no-stream", "If you use Docker: memory used by each container."),
                ]})
        if self.disk_full:
            attention.append({
                "level": "problem",
                "title": "The disk is full",
                "explain": "Programs can't save files or logs when there is no space left. Find what is using the space.",
                "commands": [
                    c("df -h", "Shows which drive is full."),
                    c("sudo du -xh / --max-depth=2 2>/dev/null | sort -rh | head -15",
                      "Lists the 15 biggest folders."),
                    c("journalctl --disk-usage", "Shows how much space the system logs take."),
                    c("docker system df", "Shows space used by Docker. Look before you delete anything."),
                    c("sudo journalctl --vacuum-size=200M",
                      "Shrinks old system logs to 200 MB. This deletes old logs."),
                ]})
        if self.segfault:
            attention.append({
                "level": "check",
                "title": f"A program crashed ({times(self.segfault, 'time')})",
                "explain": "A 'segmentation fault' means a program touched memory it shouldn't. These show which program.",
                "commands": [
                    c("dmesg -T | grep -i segfault", "Shows which program crashed, and when."),
                    c("coredumpctl list", "Lists saved crash reports, if your system keeps them."),
                ]})

        problems = sum(1 for a in attention if a["level"] == "problem")
        checks = sum(1 for a in attention if a["level"] == "check")
        if problems:
            level, text = "problem", f"{times(problems + checks, 'thing')} need your attention."
        elif checks:
            level, text = "check", f"Mostly fine. {times(checks, 'thing')} worth a quick look."
        else:
            level, text = "ok", "Good news: nothing here needs your attention."

        return {
            "verdict": {"level": level, "text": text},
            "span": {"from": self.first_ts, "to": self.last_ts, "lines": self.total},
            "happened": happened,
            "normal": normal,
            "attention": attention,
        }


def c(cmd, why):
    return {"cmd": cmd, "why": why}


def analyze(lines, brute=5, on_event=None):
    """Analyze an iterable of log lines and return the report dict."""
    a = Analyzer(brute)
    try:
        for raw in lines:
            e = a.feed(raw)
            if e and on_event and e["level"] != "hidden":
                on_event(e)
    except KeyboardInterrupt:
        pass
    return a.report()