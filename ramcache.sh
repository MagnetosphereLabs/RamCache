#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-install}"

need_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run this script with sudo."
    exit 1
  fi
}

write_controller() {
  install -d -m 755 /opt/ramcache-controller
  cat > /opt/ramcache-controller/ramcache_controller.py <<'PY'
#!/usr/bin/env python3
import json
import logging
import os
import signal
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

CONFIG_PATH = Path("/etc/ramcache-controller/config.json")
STATUS_PATH = Path("/run/ramcache-controller/status.json")
WATCH_LIST_PATH = Path("/run/ramcache-controller/watch-list.txt")

KIB = 1024
MIB = 1024 ** 2
GIB = 1024 ** 3

RUNNING = True


@dataclass(frozen=True)
class FileRec:
    path: str
    size: int
    mtime: float

@dataclass
class VmtouchRun:
    proc: subprocess.Popen
    feeder: threading.Thread
    stop_event: threading.Event

    def poll(self):
        return self.proc.poll()

def handle_signal(signum, frame):
    global RUNNING
    RUNNING = False


def load_config() -> tuple[str, dict]:
    raw = CONFIG_PATH.read_text(encoding="utf-8")
    cfg = json.loads(raw)
    return raw, cfg


def parse_size(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip().upper()
    mult = 1
    suffixes = {
        "K": 1024, "KB": 1024,
        "M": 1024**2, "MB": 1024**2,
        "G": 1024**3, "GB": 1024**3,
        "T": 1024**4, "TB": 1024**4,
    }
    for suf, factor in suffixes.items():
        if s.endswith(suf):
            mult = factor
            s = s[:-len(suf)].strip()
            break
    return int(float(s) * mult)


def parse_meminfo() -> dict[str, int]:
    data: dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            name, value = line.split(":", 1)
            data[name] = int(value.strip().split()[0]) * KIB
    return data


def path_is_excluded(path: str, excludes: list[str]) -> bool:
    path = os.path.normpath(path)
    for ex in excludes:
        if path == ex or path.startswith(ex + os.sep):
            return True
    return False


def scan_files(cfg: dict) -> list[FileRec]:
    include_paths = [os.path.normpath(p) for p in cfg["include_paths"]]
    excludes = [os.path.normpath(p) for p in cfg["exclude_prefixes"]]
    max_file_size = parse_size(cfg.get("vmtouch_max_file_size"))
    seen_realpaths: set[str] = set()
    files: list[FileRec] = []
    steps = 0

    for root in include_paths:
        try:
            root_dev = os.stat(root).st_dev
        except OSError:
            continue

        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            steps += 1
            maybe_cooldown(
                steps,
                cfg,
                every_key="scan_cooldown_every",
                sleep_key="scan_cooldown_seconds",
                default_every=4096,
                default_sleep=0.0015,
            )

            dirpath = os.path.normpath(dirpath)

            if path_is_excluded(dirpath, excludes):
                dirnames[:] = []
                continue

            kept_dirs: list[str] = []
            for d in dirnames:
                full = os.path.normpath(os.path.join(dirpath, d))
                if path_is_excluded(full, excludes):
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    continue
                if cfg.get("stay_on_filesystem", True) and st.st_dev != root_dev:
                    continue
                kept_dirs.append(d)
            dirnames[:] = kept_dirs

            for name in filenames:
                steps += 1
                maybe_cooldown(
                    steps,
                    cfg,
                    every_key="scan_cooldown_every",
                    sleep_key="scan_cooldown_seconds",
                    default_every=4096,
                    default_sleep=0.0015,
                )

                full = os.path.normpath(os.path.join(dirpath, name))
                if path_is_excluded(full, excludes):
                    continue
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if cfg.get("stay_on_filesystem", True) and st.st_dev != root_dev:
                    continue
                size = st.st_size
                if size <= 0:
                    continue
                if max_file_size is not None and size > max_file_size:
                    continue
                real = os.path.realpath(full)
                if real in seen_realpaths:
                    continue
                seen_realpaths.add(real)
                files.append(FileRec(path=full, size=size, mtime=st.st_mtime))
    return files


def maybe_cooldown(
    step: int,
    cfg: dict,
    *,
    every_key: str,
    sleep_key: str,
    default_every: int,
    default_sleep: float,
) -> None:
    every = int(cfg.get(every_key, default_every) or 0)
    delay = float(cfg.get(sleep_key, default_sleep) or 0.0)
    if every > 0 and delay > 0 and step % every == 0:
        time.sleep(delay)


def build_selection_orders(files: list[FileRec]) -> tuple[list[FileRec], list[FileRec]]:
    return (
        sorted(files, key=lambda r: (r.size, -r.mtime, r.path)),
        sorted(files, key=lambda r: (-r.size, -r.mtime, r.path)),
    )


def select_files(
    small_sorted: list[FileRec],
    large_sorted: list[FileRec],
    budget_bytes: int,
    cfg: dict,
) -> list[FileRec]:
    if budget_bytes <= 0:
        return []

    # 70% of the budget goes to smallest files first.
    # 30% goes to largest files first.
    # Then fill whatever budget remains with anything that fits.
    small_share = float(cfg.get("small_files_share_percent", 70)) / 100.0
    small_budget = int(budget_bytes * small_share)
    large_budget = budget_bytes - small_budget

    selected: list[FileRec] = []
    seen: set[str] = set()
    total = 0
    small_total = 0
    large_total = 0
    steps = 0

    for rec in small_sorted:
        steps += 1
        maybe_cooldown(
            steps,
            cfg,
            every_key="select_cooldown_every",
            sleep_key="select_cooldown_seconds",
            default_every=2048,
            default_sleep=0.001,
        )

        if small_total + rec.size > small_budget:
            break  # ascending by size, so nothing later will fit either

        selected.append(rec)
        seen.add(rec.path)
        small_total += rec.size
        total += rec.size

    for rec in large_sorted:
        steps += 1
        maybe_cooldown(
            steps,
            cfg,
            every_key="select_cooldown_every",
            sleep_key="select_cooldown_seconds",
            default_every=2048,
            default_sleep=0.001,
        )

        if rec.path in seen:
            continue
        if total + rec.size > budget_bytes:
            continue
        if large_total + rec.size > large_budget:
            continue

        selected.append(rec)
        seen.add(rec.path)
        large_total += rec.size
        total += rec.size

    for source in (small_sorted, large_sorted):
        for rec in source:
            steps += 1
            maybe_cooldown(
                steps,
                cfg,
                every_key="select_cooldown_every",
                sleep_key="select_cooldown_seconds",
                default_every=2048,
                default_sleep=0.001,
            )

            if rec.path in seen:
                continue
            if total + rec.size > budget_bytes:
                if source is small_sorted:
                    break  # ascending by size
                continue

            selected.append(rec)
            seen.add(rec.path)
            total += rec.size

    return selected


def bytes_to_gib(n: int) -> float:
    return round(n / GIB, 2)


def choose_target_bytes(meminfo: dict[str, int], cfg: dict) -> tuple[int, int, int]:
    total = meminfo["MemTotal"]
    available = meminfo["MemAvailable"]
    working_used = total - available

    target_bytes = int(total * float(cfg["base_target_ratio"]))

    thresholds = sorted(cfg["reduce_thresholds"], key=lambda x: x["working_used_ratio"])
    for row in thresholds:
        if working_used >= int(total * float(row["working_used_ratio"])):
            target_bytes = int(total * float(row["target_locked_ratio"]))

    if available < int(total * float(cfg.get("min_available_ratio", 0.125))):
        target_bytes = 0

    return target_bytes, int(working_used), int(available)


def stop_proc(proc) -> None:
    if proc is None:
        return

    runner = proc.proc if isinstance(proc, VmtouchRun) else proc

    if isinstance(proc, VmtouchRun):
        proc.stop_event.set()
        try:
            if runner.stdin is not None and not runner.stdin.closed:
                runner.stdin.close()
        except Exception:
            pass

    if runner.poll() is not None:
        if isinstance(proc, VmtouchRun) and proc.feeder.is_alive():
            proc.feeder.join(timeout=1)
        return

    try:
        runner.terminate()
        runner.wait(timeout=15)
    except subprocess.TimeoutExpired:
        runner.kill()
        runner.wait(timeout=5)
    except ProcessLookupError:
        pass
    finally:
        if isinstance(proc, VmtouchRun) and proc.feeder.is_alive():
            proc.feeder.join(timeout=1)


class Watcher:
    def __init__(self) -> None:
        self.proc: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.dirty_event = threading.Event()

    def _write_watch_list(self, cfg: dict) -> None:
        WATCH_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for p in cfg["include_paths"]:
            lines.append(os.path.normpath(p))
        for p in cfg["exclude_prefixes"]:
            lines.append("@" + os.path.normpath(p))
        WATCH_LIST_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def start(self, cfg: dict) -> None:
        self.stop()
        self._write_watch_list(cfg)
        cmd = [
            "inotifywait",
            "-m",
            "-r",
            "-q",
            "-e",
            "close_write,create,delete,move,attrib",
            "--format",
            "%w%f",
            "--fromfile",
            str(WATCH_LIST_PATH),
        ]
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.stop_event.clear()
        self.dirty_event.set()

        def reader():
            assert self.proc is not None
            try:
                for line in self.proc.stdout:
                    if self.stop_event.is_set():
                        break
                    if line:
                        self.dirty_event.set()
            except Exception:
                self.dirty_event.set()

        self.thread = threading.Thread(target=reader, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.proc is not None:
            stop_proc(self.proc)
        self.proc = None

    def mark_clean(self) -> None:
        self.dirty_event.clear()

    def is_dirty(self) -> bool:
        return self.dirty_event.is_set()

    def dead(self) -> bool:
        return self.proc is None or self.proc.poll() is not None

def compute_vmtouch_pause_plan(path_count: int, cfg: dict) -> tuple[float, int]:
    pause_seconds = float(cfg.get("vmtouch_feed_pause_seconds", 0.02) or 0.0)
    extra_budget_seconds = float(cfg.get("vmtouch_feed_target_extra_seconds", 30.0) or 0.0)

    if path_count <= 1 or pause_seconds <= 0 or extra_budget_seconds <= 0:
        return 0.0, 0

    pause_count = min(path_count - 1, int(extra_budget_seconds / pause_seconds))
    return pause_seconds, max(0, pause_count)


def start_vmtouch(cfg: dict, meminfo: dict[str, int], paths: list[str]) -> VmtouchRun:
    if "vmtouch_max_file_size_ratio" in cfg:
        max_file_size_bytes = int(meminfo["MemTotal"] * float(cfg["vmtouch_max_file_size_ratio"]))
        max_file_size_mib = max(1, max_file_size_bytes // MIB)
        max_file_size_arg = f"{max_file_size_mib}M"
    else:
        max_file_size_arg = str(cfg.get("vmtouch_max_file_size", "32G"))

    cmd = [
        "vmtouch",
        "-q",
        "-l",
        "-0",
        "-b",
        "-",
        "-m",
        max_file_size_arg,
    ]
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=False,
    )

    pause_seconds, pause_count = compute_vmtouch_pause_plan(len(paths), cfg)
    stop_event = threading.Event()

    def feed_paths() -> None:
        first_path = True
        pauses_done = 0
        total_paths = len(paths)

        try:
            assert proc.stdin is not None

            for idx, path in enumerate(paths, start=1):
                if stop_event.is_set() or proc.poll() is not None:
                    break

                if not first_path:
                    proc.stdin.write(b"\0")
                proc.stdin.write(os.fsencode(path))
                first_path = False

                target_pauses = (idx * pause_count) // total_paths
                if idx < total_paths and target_pauses > pauses_done:
                    proc.stdin.flush()

                    while pauses_done < target_pauses:
                        deadline = time.monotonic() + pause_seconds
                        while not stop_event.is_set():
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                break
                            time.sleep(min(0.25, remaining))

                        pauses_done += 1
                        if stop_event.is_set():
                            break

        except BrokenPipeError:
            pass
        except Exception:
            logging.exception("vmtouch feeder error")
        finally:
            try:
                if proc.stdin is not None and not proc.stdin.closed:
                    proc.stdin.close()
            except Exception:
                pass

    feeder = threading.Thread(target=feed_paths, daemon=True)
    feeder.start()
    return VmtouchRun(proc=proc, feeder=feeder, stop_event=stop_event)


def write_status(target_gib: int, selected: list[FileRec], meminfo: dict[str, int], last_scan_epoch: float) -> None:
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    selected_bytes = sum(r.size for r in selected)
    payload = {
        "timestamp": int(time.time()),
        "target_locked_gib": target_gib,
        "selected_files": len(selected),
        "selected_gib": bytes_to_gib(selected_bytes),
        "memtotal_gib": bytes_to_gib(meminfo["MemTotal"]),
        "memavailable_gib": bytes_to_gib(meminfo["MemAvailable"]),
        "working_used_gib": bytes_to_gib(meminfo["MemTotal"] - meminfo["MemAvailable"]),
        "cached_gib": bytes_to_gib(meminfo.get("Cached", 0)),
        "active_file_gib": bytes_to_gib(meminfo.get("Active(file)", 0)),
        "inactive_file_gib": bytes_to_gib(meminfo.get("Inactive(file)", 0)),
        "mlocked_gib": bytes_to_gib(meminfo.get("Mlocked", 0)),
        "unevictable_gib": bytes_to_gib(meminfo.get("Unevictable", 0)),
        "last_scan_epoch": int(last_scan_epoch),
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    watcher = Watcher()
    current_config_text = None
    inventory: list[FileRec] = []
    small_sorted: list[FileRec] = []
    large_sorted: list[FileRec] = []
    current_paths: list[str] = []
    current_target_bytes: Optional[int] = None
    current_vmtouch = None
    last_full_scan = 0.0

    while RUNNING:
        try:
            config_text, cfg = load_config()
            config_changed = config_text != current_config_text
            if config_changed or watcher.dead():
                current_config_text = config_text
                watcher.start(cfg)

            now = time.time()
            need_scan = (
                config_changed
                or not inventory
                or watcher.is_dirty()
                or watcher.dead()
                or now - last_full_scan >= int(cfg.get("full_rescan_interval_seconds", 86400))
            )

            if need_scan:
                inventory = scan_files(cfg)
                small_sorted, large_sorted = build_selection_orders(inventory)
                last_full_scan = now
                watcher.mark_clean()

            meminfo = parse_meminfo()
            target_bytes, _, _ = choose_target_bytes(meminfo, cfg)
            selected = select_files(small_sorted, large_sorted, target_bytes, cfg)
            new_paths = [r.path for r in selected]

            if (
                target_bytes != current_target_bytes
                or new_paths != current_paths
                or current_vmtouch is None
                or current_vmtouch.poll() is not None
            ):
                stop_proc(current_vmtouch)
                current_vmtouch = None
                if new_paths:
                    current_vmtouch = start_vmtouch(cfg, meminfo, new_paths)
                current_paths = new_paths
                current_target_bytes = target_bytes

            write_status(bytes_to_gib(current_target_bytes or 0), selected, meminfo, last_full_scan)

        except Exception:
            logging.exception("controller loop error")

        sleep_for = 10
        try:
            _, cfg = load_config()
            sleep_for = int(cfg.get("check_interval_seconds", 10))
        except Exception:
            pass

        for _ in range(max(1, sleep_for)):
            if not RUNNING:
                break
            time.sleep(1)

    watcher.stop()
    stop_proc(current_vmtouch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
  chmod 755 /opt/ramcache-controller/ramcache_controller.py
}

write_config_if_missing() {
  install -d -m 755 /etc/ramcache-controller

  if [[ ! -f /etc/ramcache-controller/config.json ]]; then
    cat > /etc/ramcache-controller/config.json <<'JSON'
{
  "include_paths": ["/"],
  "exclude_prefixes": [
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/tmp",
    "/var/cache/apt/archives",
    "/var/lib/systemd/coredump",
    "/lost+found",
    "/swapfile"
  ],
  "stay_on_filesystem": true,
  "check_interval_seconds": 180,
  "full_rescan_interval_seconds": 86400,
  "base_target_ratio": 0.70,
  "min_available_ratio": 0.125,
  "small_files_share_percent": 70,
  "vmtouch_max_file_size_ratio": 0.50,
  "vmtouch_feed_pause_seconds": 0.02,
  "vmtouch_feed_target_extra_seconds": 30,
  "reduce_thresholds": [
    {"working_used_ratio": 0.0, "target_locked_ratio": 0.70},
    {"working_used_ratio": 0.375, "target_locked_ratio": 0.50},
    {"working_used_ratio": 0.50, "target_locked_ratio": 0.35},
    {"working_used_ratio": 0.625, "target_locked_ratio": 0.21},
    {"working_used_ratio": 0.75, "target_locked_ratio": 0.0}
  ]
}
JSON
  fi
}

write_service() {
  cat > /etc/systemd/system/ramcache-controller.service <<'UNIT'
[Unit]
Description=Adaptive RAM cache controller using vmtouch
After=local-fs.target
Wants=local-fs.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 /opt/ramcache-controller/ramcache_controller.py
Restart=always
RestartSec=70
KillMode=control-group
LimitNOFILE=1048576
LimitMEMLOCK=infinity
RuntimeDirectory=ramcache-controller

[Install]
WantedBy=multi-user.target
UNIT
}

write_sysctls() {
  cat > /etc/sysctl.d/99-ramcache-inotify.conf <<'EOF'
fs.inotify.max_user_watches=1048576
EOF

  if [[ ! -f /etc/sysctl.d/99-cache-aggressive.conf ]]; then
    cat > /etc/sysctl.d/99-cache-aggressive.conf <<'EOF'
vm.vfs_cache_pressure=10
vm.vfs_cache_pressure_denom=100
EOF
  fi

  sysctl --system >/dev/null
}

install_all() {
  need_root
  export DEBIAN_FRONTEND=noninteractive
  apt update
  apt install -y python3 vmtouch inotify-tools
  write_controller
  write_config_if_missing
  write_service
  write_sysctls
  systemctl daemon-reload
  systemctl enable --now ramcache-controller.service

  echo
  echo "Installed."
  echo "Status:"
  echo "  systemctl status ramcache-controller.service --no-pager"
  echo "  python3 -m json.tool /run/ramcache-controller/status.json"
}

uninstall_all() {
  need_root
  systemctl disable --now ramcache-controller.service || true
  rm -f /etc/systemd/system/ramcache-controller.service
  rm -rf /opt/ramcache-controller
  rm -rf /etc/ramcache-controller
  rm -f /etc/sysctl.d/99-ramcache-inotify.conf
  systemctl daemon-reload
  sysctl --system >/dev/null || true

  echo
  echo "Removed ramcache-controller."
  echo "Note: /etc/sysctl.d/99-cache-aggressive.conf was left alone."
}

status_all() {
  systemctl status ramcache-controller.service --no-pager || true
  echo
  if [[ -f /run/ramcache-controller/status.json ]]; then
    python3 -m json.tool /run/ramcache-controller/status.json || cat /run/ramcache-controller/status.json
  else
    echo "No status file yet."
  fi
  echo
  grep -E 'MemAvailable|Cached|Active\(file\)|Inactive\(file\)|Mlocked|Unevictable' /proc/meminfo || true
}

case "$ACTION" in
  install) install_all ;;
  uninstall) uninstall_all ;;
  status) status_all ;;
  *)
    echo "Usage: $0 {install|uninstall|status}"
    exit 1
    ;;
esac
