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
import math
import os
import queue
import resource
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections import deque
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
CONTROLLER_WAKE_EVENT = threading.Event()
CONTROLLER_VERSION = "1.3.2"
_SCAN_STORAGE_PROFILE_CACHE: dict[tuple[str, ...], str] = {}

@dataclass(frozen=True, slots=True)
class FileRec:
    path: str
    size: int
    mtime: float
    mode: int

@dataclass
class VmtouchRun:
    proc: subprocess.Popen
    feeder: threading.Thread
    stop_event: threading.Event
    records: list[FileRec]
    bytes_locked: int

    def poll(self):
        return self.proc.poll()

def handle_signal(signum, frame):
    global RUNNING
    RUNNING = False
    CONTROLLER_WAKE_EVENT.set()


def load_config() -> tuple[str, dict]:
    raw = CONFIG_PATH.read_text(encoding="utf-8")
    cfg = json.loads(raw)
    return raw, apply_memory_size_profile(cfg)


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


def parse_memory_psi_totals() -> tuple[int, int]:
    """Return system-wide memory PSI some/full cumulative stall time in usec."""
    some_total = 0
    full_total = 0

    try:
        with open("/proc/pressure/memory", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split()
                if not parts:
                    continue
                total = 0
                for part in parts[1:]:
                    if part.startswith("total="):
                        total = int(part.split("=", 1)[1])
                        break
                if parts[0] == "some":
                    some_total = total
                elif parts[0] == "full":
                    full_total = total
    except (OSError, ValueError):
        pass

    return some_total, full_total

LOW_RAM_PROFILE_DEFAULTS = {
    "target_available_bytes": "4G",
    "target_shrink_to_available_bytes": "6G",
    "target_grow_to_available_bytes": "6G",
    "target_grow_above_available_bytes": "7G",

    "target_initial_max_bytes": "8G",
    "target_max_grow_step_bytes": "8G",
    "target_max_inflight_bytes": "8G",

    # Keep chunks small so pressure release is still surgical.
    "vmtouch_chunk_target_bytes": "512M",
    "vmtouch_chunk_max_paths": 4096,

    # React quickly to smaller changes.
    "target_relock_min_delta": "256M",

    "steam_htmlcache_budget_bytes": "768M",
    "steam_htmlcache_max_files": 2500,
    "firefox_webcache_budget_bytes": "1G",
    "firefox_webcache_max_files": 1200,
    "hytale_world_budget_bytes": "1G",
    "vrchat_content_cache_budget_bytes": "1G",

    # Avoid giant single files on low-DRAM systems.
    "vmtouch_max_file_size": "2G",

    "vmtouch_feed_pause_seconds": 0.005,
    "vmtouch_feed_target_extra_seconds": 5,

    "scan_worker_max": 16,
    "scan_io_worker_multiplier_nonrotational": 1.5,
    "scan_io_worker_multiplier_unknown": 1.25,
    "scan_cooldown_every": 512,
    "scan_cooldown_seconds": 0.003,
    "select_cooldown_every": 512,
    "select_cooldown_seconds": 0.002,
}


def apply_memory_size_profile(cfg: dict) -> dict:
    effective = dict(cfg)
    effective["memory_profile"] = "normal"

    if not bool(effective.get("low_ram_profile_enabled", True)):
        return effective

    try:
        meminfo = parse_meminfo()
        threshold = (
            parse_size(effective.get("low_ram_total_threshold_bytes", "20G"))
            or (20 * GIB)
        )
    except Exception:
        return effective

    if int(meminfo.get("MemTotal", 0)) >= int(threshold):
        return effective

    profile = dict(LOW_RAM_PROFILE_DEFAULTS)

    custom = effective.get("low_ram_profile_overrides", {})
    if isinstance(custom, dict):
        profile.update(custom)

    effective.update(profile)
    effective["memory_profile"] = "low_ram"
    return effective

class MemoryPressureAbort(Exception):
    pass


def memory_pressure_active(meminfo: dict[str, int], cfg: dict) -> bool:
    floor_available = parse_size(cfg.get("target_available_bytes", "4G")) or (4 * GIB)
    return int(meminfo["MemAvailable"]) < int(floor_available)


def maybe_abort_for_memory_pressure(step: int, cfg: dict) -> None:
    every = int(cfg.get("memory_pressure_abort_check_every", 128) or 0)
    if every <= 0 or step % every != 0:
        return

    try:
        if memory_pressure_active(parse_meminfo(), cfg):
            raise MemoryPressureAbort
    except MemoryPressureAbort:
        raise
    except Exception:
        return



class MemoryMonitor:
    """Continuously sample memory so long operations cannot blind the controller.

    The controller reacts to three independent signals: a hard MemAvailable
    floor, fast external RAM growth, and Linux PSI memory stalls.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.cfg: dict = {}
        self.samples: deque[tuple[float, int]] = deque(maxlen=8192)
        self.latest: dict[str, int] = {}
        self.ack_pressure_used: Optional[int] = None
        self.growth_guard_until = 0.0
        self.last_psi_some_total: Optional[int] = None
        self.last_psi_full_total: Optional[int] = None
        self.pending_psi_release_bytes = 0
        self.last_psi_some_delta = 0
        self.last_psi_full_delta = 0

    @staticmethod
    def _pressure_used(meminfo: dict[str, int]) -> int:
        # Do not count our own mlocked vmtouch cache as "external growth".
        # Hard MemAvailable and PSI still account for real system pressure.
        return max(
            0,
            int(meminfo.get("MemTotal", 0))
            - int(meminfo.get("MemAvailable", 0))
            - int(meminfo.get("Mlocked", 0)),
        )

    def update_config(self, cfg: dict) -> None:
        with self.lock:
            self.cfg = dict(cfg)

    def start(self, cfg: dict) -> None:
        self.update_config(cfg)
        if self.thread is not None and self.thread.is_alive():
            return

        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._run,
            name="ramcache-memory-monitor",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        CONTROLLER_WAKE_EVENT.set()
        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=2)

    def _window_floor_locked(
        self,
        now: float,
        seconds: float,
    ) -> tuple[int, int, float]:
        """Find the recent minimum without allocating a temporary sample list."""
        if not self.samples:
            return 0, 0, 0.0

        cutoff = now - max(0.1, seconds)
        current_ts, current = self.samples[-1]
        floor_ts = current_ts
        floor = current

        # Samples are time-ordered. Walk backward only through the requested
        # window; this keeps the 250 ms pressure monitor allocation-free.
        for ts, value in reversed(self.samples):
            if ts < cutoff:
                break
            if value < floor:
                floor = value
                floor_ts = ts

        return current, floor, max(0.001, current_ts - floor_ts)

    def _pending_growth_locked(
        self,
        now: float,
        cfg: dict,
    ) -> tuple[int, int, int, float]:
        rapid_window = float(cfg.get("rapid_memory_window_seconds", 60) or 60)
        fast_window = float(cfg.get("fast_memory_growth_window_seconds", 10) or 10)

        current, recent_floor, _ = self._window_floor_locked(now, rapid_window)
        _, fast_floor, fast_span = self._window_floor_locked(now, fast_window)

        if self.ack_pressure_used is None:
            self.ack_pressure_used = recent_floor

        if current < self.ack_pressure_used:
            self.ack_pressure_used = current

        if self.ack_pressure_used < recent_floor:
            self.ack_pressure_used = recent_floor

        baseline = max(recent_floor, self.ack_pressure_used)
        unacked_growth = max(0, current - baseline)
        fast_growth = max(0, current - fast_floor)
        return current, unacked_growth, fast_growth, fast_span

    def _run(self) -> None:
        while not self.stop_event.is_set():
            wake_controller = False

            try:
                meminfo = parse_meminfo()
                psi_some, psi_full = parse_memory_psi_totals()
                now = time.monotonic()
                pressure_used = self._pressure_used(meminfo)

                with self.lock:
                    self.latest = meminfo
                    self.samples.append((now, pressure_used))
                    cfg = dict(self.cfg)

                    longest_window = max(
                        float(cfg.get("rapid_memory_window_seconds", 60) or 60),
                        float(cfg.get("fast_memory_growth_window_seconds", 10) or 10),
                    )
                    cutoff = now - max(20.0, longest_window * 2.0)
                    while self.samples and self.samples[0][0] < cutoff:
                        self.samples.popleft()

                    _, unacked_growth, fast_growth, _ = self._pending_growth_locked(now, cfg)

                    rapid_threshold = (
                        parse_size(cfg.get("rapid_memory_growth_threshold_bytes", "2G"))
                        or (2 * GIB)
                    )
                    fast_threshold = (
                        parse_size(cfg.get("fast_memory_growth_threshold_bytes", "1G"))
                        or GIB
                    )
                    fast_min_unacked = (
                        parse_size(cfg.get("fast_memory_growth_min_unacked_bytes", "512M"))
                        or (512 * MIB)
                    )

                    hard_pressure = memory_pressure_active(meminfo, cfg)
                    fast_pressure = (
                        unacked_growth >= fast_min_unacked
                        and fast_growth >= fast_threshold
                    )
                    rapid_pressure = unacked_growth >= rapid_threshold

                    some_delta = 0
                    full_delta = 0
                    if self.last_psi_some_total is not None:
                        some_delta = max(0, psi_some - self.last_psi_some_total)
                    if self.last_psi_full_total is not None:
                        full_delta = max(0, psi_full - self.last_psi_full_total)

                    self.last_psi_some_total = psi_some
                    self.last_psi_full_total = psi_full
                    self.last_psi_some_delta = some_delta
                    self.last_psi_full_delta = full_delta

                    some_threshold = int(
                        cfg.get("psi_memory_some_stall_threshold_us", 100000)
                        or 100000
                    )
                    full_threshold = int(
                        cfg.get("psi_memory_full_stall_threshold_us", 20000)
                        or 20000
                    )
                    psi_pressure = (
                        (some_threshold > 0 and some_delta >= some_threshold)
                        or (full_threshold > 0 and full_delta >= full_threshold)
                    )

                    if psi_pressure:
                        release = (
                            parse_size(cfg.get("psi_memory_release_bytes", "2G"))
                            or (2 * GIB)
                        )
                        self.pending_psi_release_bytes = max(
                            self.pending_psi_release_bytes,
                            int(release),
                        )

                    wake_controller = (
                        hard_pressure
                        or fast_pressure
                        or rapid_pressure
                        or psi_pressure
                    )
            except Exception:
                pass

            if wake_controller:
                CONTROLLER_WAKE_EVENT.set()

            with self.lock:
                interval = float(
                    self.cfg.get("memory_monitor_interval_seconds", 0.25)
                    or 0.25
                )
            self.stop_event.wait(max(0.05, interval))

    def meminfo(self) -> dict[str, int]:
        with self.lock:
            latest = dict(self.latest)
        return latest if latest else parse_meminfo()

    def pending_growth_bytes(self, cfg: dict) -> int:
        with self.lock:
            _, growth, _, _ = self._pending_growth_locked(time.monotonic(), cfg)
            return growth

    def recent_growth_bytes(self, cfg: dict) -> int:
        with self.lock:
            current, recent_floor, _ = self._window_floor_locked(
                time.monotonic(),
                float(cfg.get("rapid_memory_window_seconds", 60) or 60),
            )
            return max(0, current - recent_floor)

    def recent_fast_growth_bytes(self, cfg: dict) -> int:
        with self.lock:
            current, recent_floor, _ = self._window_floor_locked(
                time.monotonic(),
                float(cfg.get("fast_memory_growth_window_seconds", 10) or 10),
            )
            return max(0, current - recent_floor)

    def consume_rapid_release_bytes(self, cfg: dict) -> tuple[int, int]:
        rapid_threshold = (
            parse_size(cfg.get("rapid_memory_growth_threshold_bytes", "2G"))
            or (2 * GIB)
        )
        fast_threshold = (
            parse_size(cfg.get("fast_memory_growth_threshold_bytes", "1G"))
            or GIB
        )
        fast_min_unacked = (
            parse_size(cfg.get("fast_memory_growth_min_unacked_bytes", "512M"))
            or (512 * MIB)
        )

        with self.lock:
            now = time.monotonic()
            current, growth, fast_growth, fast_span = self._pending_growth_locked(now, cfg)

            rapid_trigger = growth >= rapid_threshold
            fast_trigger = (
                growth >= fast_min_unacked
                and fast_growth >= fast_threshold
            )
            if not rapid_trigger and not fast_trigger:
                return 0, growth

            multiplier = float(cfg.get("rapid_memory_release_multiplier", 1.0) or 1.0)
            margin = (
                parse_size(cfg.get("rapid_memory_release_margin_bytes", "512M"))
                or (512 * MIB)
            )
            prediction_seconds = float(
                cfg.get("rapid_memory_prediction_seconds", 5)
                or 5
            )
            max_release = (
                parse_size(cfg.get("rapid_memory_max_release_bytes", "6G"))
                or (6 * GIB)
            )

            # Stay ahead of a loader that is still allocating instead of only
            # compensating for memory it has already consumed.
            rate = fast_growth / max(0.25, fast_span)
            predicted_headroom = int(
                max(0.0, rate) * max(0.0, prediction_seconds)
            )
            release = (
                int(growth * max(1.0, multiplier))
                + int(margin)
                + predicted_headroom
            )
            release = min(int(max_release), max(int(margin), release))

            self.ack_pressure_used = current
            cooldown = float(
                cfg.get("memory_pressure_regrow_cooldown_seconds", 30)
                or 30
            )
            self.growth_guard_until = max(
                self.growth_guard_until,
                now + max(0.0, cooldown),
            )

        return release, growth

    def consume_psi_release_bytes(self, cfg: dict) -> int:
        with self.lock:
            release = int(self.pending_psi_release_bytes)
            self.pending_psi_release_bytes = 0

            if release > 0:
                cooldown = float(
                    cfg.get("memory_pressure_regrow_cooldown_seconds", 30)
                    or 30
                )
                self.growth_guard_until = max(
                    self.growth_guard_until,
                    time.monotonic() + max(0.0, cooldown),
                )
        return release

    def arm_regrow_guard(self, cfg: dict) -> None:
        with self.lock:
            cooldown = float(
                cfg.get("memory_pressure_regrow_cooldown_seconds", 30)
                or 30
            )
            self.growth_guard_until = max(
                self.growth_guard_until,
                time.monotonic() + max(0.0, cooldown),
            )

    def growth_guard_active(self) -> bool:
        with self.lock:
            return time.monotonic() < self.growth_guard_until

    def psi_stall_deltas(self) -> tuple[int, int]:
        with self.lock:
            return self.last_psi_some_delta, self.last_psi_full_delta

    def should_abort_scan(self, cfg: dict) -> bool:
        try:
            meminfo = self.meminfo()
            if memory_pressure_active(meminfo, cfg):
                return True

            rapid_threshold = (
                parse_size(cfg.get("rapid_memory_growth_threshold_bytes", "2G"))
                or (2 * GIB)
            )
            fast_threshold = (
                parse_size(cfg.get("fast_memory_growth_threshold_bytes", "1G"))
                or GIB
            )
            fast_min_unacked = (
                parse_size(cfg.get("fast_memory_growth_min_unacked_bytes", "512M"))
                or (512 * MIB)
            )

            pending = self.pending_growth_bytes(cfg)
            fast = self.recent_fast_growth_bytes(cfg)

            with self.lock:
                psi_pending = self.pending_psi_release_bytes > 0

            return (
                pending >= rapid_threshold
                or (pending >= fast_min_unacked and fast >= fast_threshold)
                or psi_pending
            )
        except Exception:
            return False


def resolve_vmtouch_max_file_size_bytes(meminfo: dict[str, int], cfg: dict) -> Optional[int]:
    if "vmtouch_max_file_size_ratio" in cfg:
        return int(meminfo["MemTotal"] * float(cfg["vmtouch_max_file_size_ratio"]))
    return parse_size(cfg.get("vmtouch_max_file_size"))


def read_int_file(path: str) -> Optional[int]:
    try:
        return int(Path(path).read_text(encoding="utf-8").strip().split()[0])
    except Exception:
        return None


def write_int_file(path: str, value: int) -> None:
    Path(path).write_text(f"{int(value)}\n", encoding="utf-8")


def ensure_procfs_min(path: str, want: int) -> None:
    current = read_int_file(path)
    if current is None or current >= want:
        return
    try:
        write_int_file(path, want)
    except Exception:
        logging.exception("failed to raise %s to %d", path, want)


def ensure_nofile_limit(required_files: int, cfg: dict) -> None:
    reserve = int(cfg.get("fd_limit_reserve", 65536))
    auto_max = int(cfg.get("fd_limit_auto_max", 8388608))
    want = max(131072, required_files + reserve)
    want = min(want, auto_max)

    ensure_procfs_min("/proc/sys/fs/nr_open", want)
    ensure_procfs_min("/proc/sys/fs/file-max", max(262144, want * 2))

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = soft
        new_hard = hard

        if soft != resource.RLIM_INFINITY and soft < want:
            new_soft = want
        if hard != resource.RLIM_INFINITY and hard < want:
            new_hard = want

        if new_soft != soft or new_hard != hard:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, new_hard))
    except Exception:
        logging.exception("failed to raise RLIMIT_NOFILE")


def ensure_memlock_limit(required_bytes: int, cfg: dict) -> None:
    reserve = parse_size(cfg.get("memlock_limit_reserve", "1G")) or GIB
    minimum = parse_size(cfg.get("memlock_limit_min", "1G")) or GIB
    want = max(minimum, required_bytes + reserve)

    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
        new_soft = soft
        new_hard = hard

        if soft != resource.RLIM_INFINITY and soft < want:
            new_soft = want
        if hard != resource.RLIM_INFINITY and hard < want:
            new_hard = want

        if new_soft != soft or new_hard != hard:
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (new_soft, new_hard))
    except Exception:
        logging.exception("failed to raise RLIMIT_MEMLOCK")


def ensure_limits_for_selection(selected: list[FileRec], cfg: dict) -> None:
    ensure_nofile_limit(len(selected), cfg)
    ensure_memlock_limit(sum(r.size for r in selected), cfg)

def path_has_prefix(path: str, prefixes: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix + os.sep) for prefix in prefixes)


def path_contains_any(path: str, needles: tuple[str, ...]) -> bool:
    return any(needle in path for needle in needles)


def path_is_excluded(path: str, excludes: list[str]) -> bool:
    path = os.path.normpath(path)
    for ex in excludes:
        if path == ex or path.startswith(ex + os.sep):
            return True
    return False


def existing_dir(path: Path) -> Optional[str]:
    try:
        if path.is_dir():
            return os.path.normpath(str(path))
    except OSError:
        return None
    return None


def iter_home_dirs() -> list[Path]:
    homes: list[Path] = [Path("/root")]
    base = Path("/home")

    try:
        for p in base.iterdir():
            try:
                if p.is_dir():
                    homes.append(p)
            except OSError:
                continue
    except OSError:
        pass

    return homes


def parse_steam_libraryfolders_vdf(path: Path) -> list[str]:
    libraries: list[str] = []

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return libraries

    for line in lines:
        s = line.strip()
        if not s.startswith('"path"'):
            continue

        parts = s.split('"')
        if len(parts) >= 4:
            value = parts[3].replace("\\\\", "\\")
            if value:
                libraries.append(value)

    return libraries


def discover_extra_include_paths(cfg: dict) -> list[str]:
    if not bool(cfg.get("auto_include_common_app_paths", True)):
        return []

    paths: list[str] = []

    def add(path: Path) -> None:
        found = existing_dir(path)
        if found is not None:
            paths.append(found)

    # System app/runtime roots. These are where installed app runtimes, Flatpaks, Snaps, /opt apps, and local apps live.
    for p in (
        Path("/opt"),
        Path("/usr/local/bin"),
        Path("/usr/local/lib"),
        Path("/usr/local/libexec"),
        Path("/snap"),
        Path("/var/lib/flatpak/app"),
        Path("/var/lib/flatpak/runtime"),
        Path("/var/lib/flatpak/exports"),
        Path("/var/lib/snapd/desktop"),
    ):
        add(p)

    for home in iter_home_dirs():
        # User app/runtime roots. Deliberately avoid broad "cache all of home".
        for p in (
            home / ".local/bin",
            home / ".local/share/applications",
            home / ".local/share/icons",
            home / ".local/share/fonts",
            home / ".local/share/mime",
            home / ".local/share/flatpak/app",
            home / ".local/share/flatpak/runtime",
            home / ".local/share/flatpak/exports",
            home / ".var/app/org.mozilla.firefox",

            # Browser profile startup state.
            home / ".mozilla/firefox",
            home / ".config/google-chrome",
            home / ".config/chromium",
            home / ".config/BraveSoftware",
            home / ".config/bravesoftware",
            home / ".config/vivaldi",
            home / ".config/opera",

            # Common Electron / desktop apps.
            home / ".config/discord",
            home / ".config/Discord",
            home / ".config/vesktop",
            home / ".config/Vesktop",
            home / ".config/obs-studio",
            home / ".config/Code",
            home / ".config/code",
            home / ".config/VSCodium",
            home / ".config/vscodium",

            # COSMIC / Pop desktop app state.
            home / ".config/cosmic",
            home / ".config/com.system76.CosmicSettings",
            home / ".config/com.system76.CosmicFiles",

            # High-value caches, not general browser HTTP cache.
            home / ".cache/fontconfig",
            home / ".cache/mesa_shader_cache",
            home / ".cache/nvidia",

            # Native Steam layouts seen on Debian/Ubuntu/Pop and common Steam symlinks.
            home / ".steam/root",
            home / ".steam/steam",
            home / ".steam/debian-installation",
            home / ".local/share/Steam",

            # Flatpak Steam layout.
            home / ".var/app/com.valvesoftware.Steam",
            home / ".var/app/com.valvesoftware.Steam/.local/share/Steam",
        ):
            add(p)

        steam_roots = (
            home / ".steam/root",
            home / ".steam/steam",
            home / ".steam/debian-installation",
            home / ".local/share/Steam",
            home / ".var/app/com.valvesoftware.Steam/.local/share/Steam",
        )

        for steam_root in steam_roots:
            for p in (
                steam_root / "appcache",
                steam_root / "config",
                steam_root / "package",
                steam_root / "public",
                steam_root / "resource",
                steam_root / "ubuntu12_32",
                steam_root / "ubuntu12_64",
                steam_root / "compatibilitytools.d",
                steam_root / "steamapps",
                steam_root / "steamapps/common",
                steam_root / "steamapps/shadercache",
                steam_root / "steamapps/compatdata",
            ):
                add(p)

        steam_vdfs = (
            home / ".steam/root/steamapps/libraryfolders.vdf",
            home / ".steam/steam/steamapps/libraryfolders.vdf",
            home / ".steam/debian-installation/steamapps/libraryfolders.vdf",
            home / ".local/share/Steam/steamapps/libraryfolders.vdf",
            home / ".var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/libraryfolders.vdf",
        )

        for vdf in steam_vdfs:
            for library in parse_steam_libraryfolders_vdf(vdf):
                library_path = Path(library)
                for p in (
                    library_path / "steamapps",
                    library_path / "steamapps/common",
                    library_path / "steamapps/shadercache",
                    library_path / "steamapps/compatdata",
                ):
                    add(p)

    deduped: list[str] = []
    seen: set[str] = set()

    for p in paths:
        norm = os.path.normpath(p)
        if norm in seen:
            continue
        seen.add(norm)
        deduped.append(norm)

    return deduped


def root_allows_cross_filesystem(root: str, cfg: dict) -> bool:
    root = os.path.normpath(root)
    cross_roots = tuple(
        os.path.normpath(p)
        for p in cfg.get("cross_filesystem_include_roots", ["/snap"])
    )
    return path_has_prefix(root, cross_roots)


def path_is_under(child: str, parent: str) -> bool:
    child = os.path.normpath(child)
    parent = os.path.normpath(parent)

    if parent == "/":
        return child.startswith("/")
    return child == parent or child.startswith(parent + os.sep)


def safe_dev(path: str) -> Optional[int]:
    try:
        return os.stat(path).st_dev
    except OSError:
        return None


def build_include_paths(cfg: dict) -> list[str]:
    raw_paths: list[str] = []

    for p in cfg["include_paths"]:
        norm = os.path.normpath(p)
        if norm not in raw_paths:
            raw_paths.append(norm)

    for p in discover_extra_include_paths(cfg):
        norm = os.path.normpath(p)
        if norm not in raw_paths:
            raw_paths.append(norm)

    # Avoid walking /home, /opt, etc. twice when they are already covered by /
    # on the same filesystem. Keep them when they are separate filesystems.
    ordered = sorted(raw_paths, key=lambda p: (p.count(os.sep), len(p), p))
    kept: list[str] = []

    stay_on_filesystem = bool(cfg.get("stay_on_filesystem", True))

    for path in ordered:
        path_dev = safe_dev(path)
        redundant = False

        for parent in kept:
            if not path_is_under(path, parent):
                continue

            parent_dev = safe_dev(parent)

            if not stay_on_filesystem or root_allows_cross_filesystem(parent, cfg):
                redundant = True
                break

            if path_dev is not None and parent_dev is not None and path_dev == parent_dev:
                redundant = True
                break

        if not redundant:
            kept.append(path)

    return kept


HOT_SYSTEM_PREFIXES = (
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/etc",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/libexec",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/local/libexec",
)

APP_RUNTIME_PREFIXES = (
    "/opt",
    "/usr/local",
    "/var/lib/flatpak/app",
    "/var/lib/flatpak/runtime",
    "/var/lib/flatpak/exports",
    "/var/lib/snapd/desktop",
    "/snap",
)

BROWSER_RUNTIME_PREFIXES = (
    "/usr/lib/firefox",
    "/usr/lib/firefox-esr",
    "/usr/share/firefox",
    "/usr/lib/thunderbird",
    "/usr/lib/chromium",
    "/usr/lib/chromium-browser",
    "/opt/google/chrome",
    "/opt/brave.com",
    "/opt/microsoft/msedge",
    "/snap/firefox",
    "/snap/chromium",
    "/var/lib/flatpak/app/org.mozilla.firefox",
)

DESKTOP_SUPPORT_PREFIXES = (
    "/etc/xdg",
    "/etc/fonts",
    "/usr/share/applications",
    "/usr/local/share/applications",
    "/usr/share/appdata",
    "/usr/share/metainfo",
    "/usr/share/desktop-directories",
    "/usr/share/icons",
    "/usr/share/pixmaps",
    "/usr/share/mime",
    "/usr/share/glib-2.0",
    "/usr/share/dbus-1",
    "/usr/share/xdg-desktop-portal",
    "/usr/share/xdg-desktop-portal-portals",
    "/usr/share/systemd",
    "/usr/share/polkit-1",
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "/usr/share/themes",
    "/usr/share/sounds",
    "/usr/share/thumbnailers",
    "/usr/share/wayland",
    "/usr/share/wayland-sessions",
    "/usr/share/gtk-3.0",
    "/usr/share/gtk-4.0",
    "/usr/share/qt5",
    "/usr/share/qt6",
    "/usr/share/libinput",
    "/usr/share/hwdata",
    "/usr/share/xsessions",
    "/usr/share/x11",
    "/usr/share/vulkan",
    "/usr/share/drirc.d",
    "/usr/share/alsa",
    "/usr/share/pipewire",
    "/usr/share/pulseaudio",
    "/usr/share/gstreamer-1.0",
    "/usr/share/kservices5",
    "/usr/share/kservicetypes5",
    "/usr/share/kxmlgui5",
    "/usr/share/plasma",
    "/usr/share/gnome-shell",
    "/usr/share/nautilus",
    "/usr/share/cosmic",
    "/usr/share/cinnamon",
    "/usr/share/nemo",
    "/usr/share/xapps",
    "/usr/share/mate",
    "/usr/share/caja",
    "/usr/share/xfce4",
    "/usr/share/thunar",
    "/usr/share/gvfs",
    "/var/cache/fontconfig",
)

GRAPHICS_AUDIO_RUNTIME_SUBSTRINGS = (
    "/mesa",
    "/vulkan",
    "/opengl",
    "/egl",
    "/glvnd",
    "/vaapi",
    "/vdpau",
    "/pipewire",
    "/pulseaudio",
    "/alsa",
    "/gstreamer",
    "/wireplumber",
)

HOT_USER_SUBSTRINGS = (
    "/.local/bin/",
    "/.local/share/applications/",
    "/.local/share/icons/",
    "/.local/share/fonts/",
    "/.local/share/mime/",
    "/.local/share/flatpak/app/",
    "/.local/share/flatpak/runtime/",
    "/.local/share/flatpak/exports/",
    "/.config/autostart/",
    "/.config/systemd/",
    "/.config/dconf/",
    "/.config/gtk-3.0/",
    "/.config/gtk-4.0/",
    "/.config/fontconfig/",
    "/.config/nautilus/",
    "/.config/cinnamon/",
    "/.config/nemo/",
    "/.config/mate/",
    "/.config/xfce4/",
    "/.config/gnome-shell/",
    "/.local/share/gvfs-metadata/",
    "/.themes/",
    "/.icons/",
    "/.fonts/",
    "/.cache/fontconfig/",
)

BROWSER_PROFILE_SUBSTRINGS = (
    "/.mozilla/firefox/",
    "/.config/google-chrome/",
    "/.config/chromium/",
    "/.config/bravesoftware/",
    "/.config/microsoft-edge/",
    "/.config/vivaldi/",
    "/.config/opera/",
)

USER_APP_SUBSTRINGS = (
    "/.config/discord/",
    "/.config/vesktop/",
    "/.config/obs-studio/",
    "/.config/code/",
    "/.config/vscode/",
    "/.config/vscodium/",
    "/.config/slack/",
    "/.config/teams-for-linux/",
    "/.config/cosmic/",
    "/.config/com.system76.cosmicsettings/",
    "/.config/com.system76.cosmicfiles/",
)

ELECTRON_APP_SUBSTRINGS = (
    "/discord/",
    "/vesktop/",
    "/resources/app/",
    "/resources/app.asar",
    "/app.asar",
)

VRCHAT_APPID = "438100"

STEAM_SUBSTRINGS = (
    "/.steam/root/",
    "/.steam/steam/",
    "/.steam/debian-installation/",
    "/.local/share/steam/",
    "/.var/app/com.valvesoftware.steam/",
    "/steamapps/",
    "/compatibilitytools.d/",
    "/proton",
    "/steam-runtime",
    "/steamlinuxruntime",
)

STEAM_FAST_SUBSTRINGS = (
    "/appcache/",
    "/config/",
    "/package/",
    "/public/",
    "/resource/",
    "/clientui/",
    "/ubuntu12_32/",
    "/ubuntu12_64/",
    "/steamrt/",
    "/steamrt64/",
    "/steam-runtime/",
    "/steam-runtime-heavy/",
    "/compatibilitytools.d/",
    "/steamapps/common/proton",
    "/steamapps/common/steamlinuxruntime",
    "/steamapps/common/steam linux runtime",
    "/steamapps/common/steamworks shared",
    "/steamapps/common/vrchat/",
    f"/steamapps/compatdata/{VRCHAT_APPID}/",
)

COSMIC_SUBSTRINGS = (
    "/cosmic",
    "/com.system76.cosmic",
    "/pop-cosmic",
    "/start-cosmic",
)

VR_RUNTIME_SUBSTRINGS = (
    "/openvr",
    "/steamvr",
    "/wivrn",
    "/wayvr",
    "/monado",
    "/vrchat",
    "/alvr",
    "/xrizer",
    "/openhmd",
)

SHADER_CACHE_SUBSTRINGS = (
    "/mesa_shader_cache/",
    "/steamapps/shadercache/",
    "/shadercache/",
    "/glcache/",
    "/.nv/glcache/",
    "/.cache/nvidia/",
    "/.cache/mesa_shader_cache/",
    "/dxvk_state_cache",
    "/vkd3d",
)

HARD_COLD_PREFIXES = (
    "/usr/share/doc",
    "/usr/share/man",
    "/usr/share/help",
    "/usr/share/gtk-doc",
    "/usr/share/licenses",
    "/usr/src",
    "/var/log",
    "/var/crash",
    "/var/lib/systemd/coredump",
    "/var/lib/docker",
    "/var/lib/containers",
    "/var/lib/libvirt",
    "/var/lib/flatpak/repo",
    "/var/lib/snapd/cache",
    "/var/lib/snapd/snaps",
)

BROWSER_HTTP_CACHE_SUBSTRINGS = (
    "/cache/cache_data/",
    "/cache2/entries/",
    "/code cache/",
    "/service worker/cachestorage/",
    "/application cache/",
    "/gpucache/",
    "/grshadercache/",
)

PRUNE_DIR_SUBSTRINGS = (
    "/.local/share/trash/",
    "/.trash/",
    "/.git/",
    "/.svn/",
    "/.hg/",
    "/cmakefiles/",
    "/target/debug/",
    "/target/release/",
)

MEDIA_SUFFIXES = (
    ".mp4", ".m4v", ".mkv", ".mov", ".webm", ".avi", ".flv", ".wmv",
    ".mp3", ".flac", ".wav", ".ogg", ".opus", ".m4a", ".aac",
    ".jpg", ".jpeg", ".heic", ".heif", ".raw", ".cr2", ".nef", ".arw",
)

ARCHIVE_SUFFIXES = (
    ".zip", ".7z", ".rar", ".tar", ".tgz", ".tar.gz", ".tar.xz",
    ".tar.zst", ".gz", ".xz", ".zst", ".bz2",
)

PACKAGE_IMAGE_SUFFIXES = (
    ".deb", ".rpm", ".snap", ".flatpak", ".iso", ".img", ".qcow2",
    ".vdi", ".vmdk", ".ova",
)

DOCUMENT_SUFFIXES = (
    ".pdf", ".epub", ".mobi", ".azw", ".azw3", ".cbz", ".cbr",
    ".doc", ".docx", ".odt", ".rtf", ".ppt", ".pptx", ".xls", ".xlsx",
)

GAME_ASSET_SUFFIXES = (
    ".pak", ".vpk", ".ucas", ".utoc", ".bundle", ".rpak", ".forge",
    ".bsa", ".ba2", ".wad", ".pk3", ".iwd", ".wem", ".bnk",
)

CONFIG_SUFFIXES = (
    ".conf", ".cfg", ".ini", ".json", ".toml", ".yaml", ".yml",
    ".xml", ".desktop", ".service", ".socket", ".target", ".timer",
    ".mount", ".automount", ".path", ".rules", ".policy", ".theme",
    ".index", ".list", ".vdf", ".acf", ".manifest",
)

RUNTIME_SUFFIXES = (
    ".so", ".dll", ".exe", ".bin", ".appimage", ".node", ".jar",
    ".py", ".pyc", ".pyo", ".qml", ".js", ".mjs", ".cjs", ".lua",
    ".rb", ".pl", ".pm", ".class", ".wasm",
)

# App payloads often contain code/resources that are neither ELF executables
# nor shared objects. These are useful startup/runtime reads, unlike bulk user
# media. Size caps below prevent opaque giant assets from being promoted.
APP_CODE_RESOURCE_SUFFIXES = (
    ".asar", ".pak", ".dat", ".gresource", ".typelib", ".qmltypes", ".mo",
    ".wasm",
)

APP_RUNTIME_SUBSTRINGS = (
    "/.local/share/flatpak/app/",
    "/.local/share/flatpak/runtime/",
)

GENERIC_SANDBOX_APP_STATE_SUBSTRINGS = (
    "/.var/app/",
)

APP_SHARE_CODE_SUFFIXES = (
    ".py", ".pyc", ".pyo", ".qml", ".qmltypes", ".js", ".mjs", ".cjs",
    ".wasm", ".gresource", ".typelib", ".mo",
)

APP_CODE_RESOURCE_MAX = 256 * MIB
APP_SHARE_CODE_MAX = 128 * MIB

FONT_SUFFIXES = (
    ".ttf", ".otf", ".ttc", ".woff", ".woff2", ".pcf", ".pfb",
)

ICON_SUFFIXES = (
    ".svg", ".svgz", ".png", ".xpm", ".ico",
)

SHADER_SUFFIXES = (
    ".spv", ".cache", ".foz", ".toc",
)

HOT_SPECIAL_NAMES = {
    "ld.so.cache",
    "locale-archive",
    "gschemas.compiled",
    "mime.cache",
    "mimeinfo.cache",
    "icon-theme.cache",
    "index.theme",
    "recently-used.xbel",
    "mimeapps.list",
    "monitors.xml",
    "user-dirs.dirs",
    "user-dirs.locale",
}

BROWSER_STARTUP_NAMES = {
    "prefs.js",
    "sessionstore.jsonlz4",
    "extensions.json",
    "addons.json",
    "compatibility.ini",
    "profiles.ini",
    "places.sqlite",
    "favicons.sqlite",
    "permissions.sqlite",
    "cookies.sqlite",
    "storage.sqlite",
}

STEAM_STARTUP_NAMES = {
    "libraryfolders.vdf",
    "config.vdf",
    "loginusers.vdf",
    "shortcuts.vdf",
    "localconfig.vdf",
    "system.reg",
    "user.reg",
    "userdef.reg",
}

ELECTRON_RUNTIME_NAMES = {
    "app.asar",
    "omni.ja",
    "icudtl.dat",
    "resources.pak",
    "snapshot_blob.bin",
    "v8_context_snapshot.bin",
    "chrome_100_percent.pak",
    "chrome_200_percent.pak",
}

STEAM_UI_CACHE_SUBSTRINGS = (
    "/config/htmlcache/default/cache/cache_data/",
    "/config/htmlcache/default/code cache/",
    "/config/htmlcache/default/local storage/leveldb/",
    "/config/htmlcache/default/session storage/",
    "/config/htmlcache/default/shared dictionary/",
    "/config/htmlcache/default/gpucache/",
)

FIREFOX_WEB_CACHE_SUBSTRINGS = (
    "/.cache/mozilla/firefox/",
    "/.mozilla/firefox/",
    "/.var/app/org.mozilla.firefox/cache/mozilla/firefox/",
)

FIREFOX_WEB_CACHE_TARGET_SUBSTRINGS = (
    "/cache2/entries/",
    "/cache2/index",
    "/startupcache/",
    "/offlinecache/",
)

HYTALE_SUBSTRINGS = (
    "/.var/app/com.hypixel.hytalelauncher/data/hytale/",
)

HYTALE_WORLD_CHUNK_SUBSTRINGS = (
    "/userdata/saves/",
    "/universe/worlds/",
    "/chunks/",
)

HYTALE_WORLD_DATA_COLD_SUBSTRINGS = (
    "/logs/",
    "/telemetry/",
    "/.sentry-cache/",
)

HYTALE_WORLD_DATA_COLD_SUFFIXES = (
    ".log",
    ".log.gz",
    ".jsonl.gz",
    ".tmp",
    ".bak",
)

VRCHAT_RUNTIME_SUBSTRINGS = (
    "/steamapps/common/vrchat/",
    f"/steamapps/compatdata/{VRCHAT_APPID}/",
)

VRCHAT_CONTENT_CACHE_SUBSTRINGS = (
    f"/steamapps/compatdata/{VRCHAT_APPID}/pfx/drive_c/users/steamuser/appdata/locallow/vrchat/vrchat/cache-windowsplayer/",
)

SELECTIVE_STEAM_RUNTIME_SUBSTRINGS = (
    "/clientui/",
    "/steamrt/",
    "/steamrt64/",
    "/steam-runtime/",
    "/steam-runtime-heavy/",
    "/steamapps/common/proton",
    "/steamapps/common/steamlinuxruntime",
    "/steamapps/common/steam linux runtime",
    "/steamapps/common/steamworks shared/",
    "/compatibilitytools.d/",
) + VRCHAT_RUNTIME_SUBSTRINGS

STEAM_UI_CACHE_FILE_MAX = 64 * MIB
FIREFOX_WEB_CACHE_FILE_MAX = 128 * MIB
HYTALE_WORLD_FILE_MAX = 1 * GIB
VRCHAT_CONTENT_CACHE_FILE_MAX = 1 * GIB

RECENCY_FIRST_BUDGET_KEYS = {
    "steam_htmlcache",
    "firefox_webcache",
    "hytale_world",
    "vrchat_content_cache",
}

VIP_FULL_APP_PREFIXES = (
    # COSMIC built-ins.
    "/usr/bin/cosmic-files",
    "/usr/bin/cosmic-files-applet",
    "/usr/bin/cosmic-settings",
    "/usr/bin/cosmic-settings-daemon",
    "/usr/bin/cosmic-store",
    "/usr/share/cosmic/com.system76.cosmicsettings.shortcuts",
    "/usr/share/cosmic/com.system76.cosmicsettings.windowrules",

    # FileZilla.
    "/usr/bin/filezilla",
    "/usr/bin/fzsftp",
    "/usr/bin/fzputtygen",
    "/usr/share/filezilla",

    # OBS.
    "/usr/bin/obs",
    "/usr/lib/x86_64-linux-gnu/obs-plugins",
    "/usr/lib/x86_64-linux-gnu/obs-scripting",
    "/usr/lib/x86_64-linux-gnu/libobs.so",
    "/usr/share/obs",

    # RustDesk.
    "/usr/bin/rustdesk",
    "/usr/share/rustdesk",

    # Vesktop.
    "/opt/vesktop",
    "/usr/bin/vesktop",

    # Shotcut system Flatpak install.
    "/var/lib/flatpak/app/org.shotcut.shotcut",
    "/var/lib/flatpak/exports/bin/org.shotcut.shotcut",

    # WiVRn system Flatpak install.
    "/var/lib/flatpak/app/io.github.wivrn.wivrn",
    "/var/lib/flatpak/exports/bin/io.github.wivrn.wivrn",
)

VIP_FULL_APP_HOME_MARKERS = (
    # COSMIC user state.
    "/.config/cosmic/com.system76.cosmicfiles",
    "/.config/cosmic/com.system76.cosmicsettings",
    "/.config/cosmic/com.system76.cosmicstore",
    "/.cache/cosmic-settings",
    "/.cache/cosmic-store",

    # FileZilla user state.
    "/.cache/filezilla",
    "/.config/filezilla",

    # Kdenlive user Flatpak install/state.
    "/.local/share/flatpak/app/org.kde.kdenlive",
    "/.local/share/flatpak/exports/bin/org.kde.kdenlive",
    "/.var/app/org.kde.kdenlive",

    # OBS user state.
    "/.config/obs-studio",

    # RustDesk user state.
    "/.config/rustdesk",

    # Shotcut user Flatpak state.
    "/.var/app/org.shotcut.shotcut",

    # Vesktop app/user state.
    "/.config/vesktop",

    # VLC user Flatpak install/state.
    "/.local/share/flatpak/app/org.videolan.vlc",
    "/.local/share/flatpak/exports/bin/org.videolan.vlc",
    "/.var/app/org.videolan.vlc",

    # WiVRn runtime/user state.
    "/.cache/wivrn",
    "/.config/openvr",
    "/.config/openxr",
    "/.var/app/io.github.wivrn.wivrn",
)

VIP_FULL_APP_PATH_NEEDLES = (
    # App desktop files, icons, metainfo, translations, and package-adjacent data.
    "/com.system76.cosmicfiles",
    "/com.system76.cosmicsettings",
    "/com.system76.cosmicstore",
    "/filezilla.",
    "/filezilla/",
    "/libfilezilla",
    "/libfzclient",
    "/lc_messages/filezilla.mo",
    "/org.kde.kdenlive",
    "/com.obsproject.studio",
    "/obs-plugins/",
    "/obs-scripting/",
    "/libobs",
    "/rustdesk.",
    "/rustdesk/",
    "/org.shotcut.shotcut",
    "/vesktop.",
    "/org.videolan.vlc",
    "/io.github.wivrn.wivrn",
)

STEAM_CLIENT_VIP_TOPLEVEL_DIRS = {
    "appcache",
    "clientui",
    "config",
    "friends",
    "graphics",
    "linux32",
    "linux64",
    "package",
    "public",
    "resource",
    "steamrt64",
    "ubuntu12_32",
    "ubuntu12_64",
}

STEAM_CLIENT_VIP_TOPLEVEL_FILES = {
    "steam",
    "steam.sh",
    "steam_msg.sh",
}

STEAM_ROOT_MARKERS = (
    "/.steam/root/",
    "/.steam/steam/",
    "/.steam/debian-installation/",
    "/.local/share/steam/",
    "/.var/app/com.valvesoftware.steam/.local/share/steam/",
)


def marker_root_match(path: str, marker: str) -> bool:
    idx = path.find(marker)
    if idx < 0:
        return False

    end = idx + len(marker)
    return end == len(path) or path[end] == os.sep


def path_contains_root_marker(path: str, markers: tuple[str, ...]) -> bool:
    return any(marker_root_match(path, marker) for marker in markers)


def steam_root_tail(path: str) -> Optional[str]:
    lower = os.path.normpath(path).lower()

    for marker in STEAM_ROOT_MARKERS:
        idx = lower.find(marker)
        if idx >= 0:
            return lower[idx + len(marker):].strip(os.sep)

    return None


def is_vip_steam_client_path(path: str) -> bool:
    tail = steam_root_tail(path)
    if not tail:
        return False

    if tail in STEAM_CLIENT_VIP_TOPLEVEL_FILES:
        return True

    if tail == "steamapps/libraryfolders.vdf":
        return True

    if tail.startswith("steamapps/appmanifest_") and tail.endswith(".acf"):
        return os.sep not in tail[len("steamapps/"):]

    top = tail.split(os.sep, 1)[0]
    return top in STEAM_CLIENT_VIP_TOPLEVEL_DIRS


def is_vip_full_app_path(path: str) -> bool:
    path = os.path.normpath(path).lower()

    for prefix in VIP_FULL_APP_PREFIXES:
        prefix = os.path.normpath(prefix).lower()
        if path == prefix or path.startswith(prefix + os.sep):
            return True

    if path_contains_root_marker(path, VIP_FULL_APP_HOME_MARKERS):
        return True

    if path_contains_any(path, VIP_FULL_APP_PATH_NEEDLES):
        return True

    return False


def is_vip_vrchat_runtime_path(path: str) -> bool:
    path = os.path.normpath(path).lower()

    if is_vrchat_content_cache_path(path):
        return False

    if f"/steamapps/shadercache/{VRCHAT_APPID}/" in path:
        return False

    if path.endswith(f"/steamapps/appmanifest_{VRCHAT_APPID}.acf"):
        return True

    return (
        f"/steamapps/common/vrchat/" in path
        or f"/steamapps/compatdata/{VRCHAT_APPID}/" in path
    )


def vrchat_content_cache_unit_root(path: str) -> Optional[str]:
    lower = os.path.normpath(path).lower()
    marker = VRCHAT_CONTENT_CACHE_SUBSTRINGS[0]

    idx = lower.find(marker)
    if idx < 0:
        return None

    after = idx + len(marker)
    next_sep = lower.find(os.sep, after)

    if next_sep < 0:
        return lower

    return lower[:next_sep]


def is_vip_path(path: str) -> bool:
    path = os.path.normpath(path).lower()
    return (
        is_vip_full_app_path(path)
        or is_vip_steam_client_path(path)
        or is_vip_vrchat_runtime_path(path)
        or is_vrchat_content_cache_path(path)
    )


def vip_classification(path: str, name: str, size: int) -> Optional[tuple[int, int, int]]:
    if is_vrchat_content_cache_path(path):
        if size <= VRCHAT_CONTENT_CACHE_FILE_MAX:
            # VIP, but after full app/runtime VIP. select_files() enforces the
            # recent-unit, >=1M unit, and 2G total cap.
            return (-90, 10000, 0)
        return (99, 0, 0)

    if (
        is_vip_full_app_path(path)
        or is_vip_steam_client_path(path)
        or is_vip_vrchat_runtime_path(path)
    ):
        return (-100, 10000, 0)

    return None


def is_steam_ui_cache_path(path: str) -> bool:
    return path_contains_any(path, STEAM_UI_CACHE_SUBSTRINGS)


def is_firefox_web_cache_path(path: str) -> bool:
    return (
        path_contains_any(path, FIREFOX_WEB_CACHE_SUBSTRINGS)
        and path_contains_any(path, FIREFOX_WEB_CACHE_TARGET_SUBSTRINGS)
    )


def is_hytale_path(path: str) -> bool:
    return path_contains_any(path, HYTALE_SUBSTRINGS)


HYTALE_WORLD_ROOT_FILES = {
    "bans.json",
    "config.json",
    "permissions.json",
    "whitelist.json",
    "client_metadata.json",
}


def is_hytale_world_save_path(path: str) -> bool:
    return (
        is_hytale_path(path)
        and "/userdata/saves/" in path
    )


def is_hytale_world_chunk_path(path: str) -> bool:
    return (
        is_hytale_world_save_path(path)
        and path_contains_any(path, HYTALE_WORLD_CHUNK_SUBSTRINGS)
        and path.endswith(".region.bin")
    )


def is_hytale_world_data_path(path: str) -> bool:
    if not is_hytale_world_save_path(path):
        return False

    name = os.path.basename(path)

    if path_contains_any(path, HYTALE_WORLD_DATA_COLD_SUBSTRINGS):
        return False

    if name.endswith(HYTALE_WORLD_DATA_COLD_SUFFIXES):
        return False

    return (
        is_hytale_world_chunk_path(path)
        or "/universe/worlds/" in path
        or "/universe/players/" in path
        or "/mods/" in path
        or name in HYTALE_WORLD_ROOT_FILES
    )


def is_hytale_runtime_path(path: str, name: str) -> bool:
    if not is_hytale_path(path):
        return False

    return (
        name in {
            "hytale-launcher",
            "hytaleclient",
            "hytaleserver.jar",
            "libjvm.so",
            "libmsquic.so",
            "libnoesis.so",
            "libdiscord_partner_sdk.so",
            "libquiche.so",
        }
        or "/package/game/latest/client/" in path
        or "/package/game/latest/server/" in path
        or "/package/jre/latest/" in path
    )


def is_vrchat_runtime_path(path: str) -> bool:
    return path_contains_any(path, VRCHAT_RUNTIME_SUBSTRINGS)


def is_vrchat_content_cache_path(path: str) -> bool:
    return path_contains_any(path, VRCHAT_CONTENT_CACHE_SUBSTRINGS)


def is_selective_steam_runtime_path(path: str) -> bool:
    return path_contains_any(path, SELECTIVE_STEAM_RUNTIME_SUBSTRINGS)


def is_targeted_browser_like_cache_path(path: str) -> bool:
    return (
        is_steam_ui_cache_path(path)
        or is_firefox_web_cache_path(path)
        or is_vrchat_content_cache_path(path)
    )


def file_is_executable(rec: FileRec) -> bool:
    return bool(rec.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def is_shared_library_name(name: str) -> bool:
    return name.endswith(".so") or ".so." in name


def is_browser_profile_path(path: str) -> bool:
    return path_contains_any(path, BROWSER_PROFILE_SUBSTRINGS)


def is_browser_http_cache_path(path: str) -> bool:
    return path_contains_any(path, BROWSER_HTTP_CACHE_SUBSTRINGS)


def is_steam_path(path: str) -> bool:
    return path_contains_any(path, STEAM_SUBSTRINGS)


def is_vr_path(path: str) -> bool:
    return path_contains_any(path, VR_RUNTIME_SUBSTRINGS)


def is_shader_cache_path(path: str) -> bool:
    return path_contains_any(path, SHADER_CACHE_SUBSTRINGS)


def is_app_runtime_path(path: str) -> bool:
    return (
        path_has_prefix(path, APP_RUNTIME_PREFIXES)
        or path_has_prefix(path, BROWSER_RUNTIME_PREFIXES)
        or path_contains_any(path, APP_RUNTIME_SUBSTRINGS)
        or path_contains_any(path, ELECTRON_APP_SUBSTRINGS)
    )


def is_generic_sandbox_app_state_path(path: str) -> bool:
    return path_contains_any(path, GENERIC_SANDBOX_APP_STATE_SUBSTRINGS)


def is_app_code_resource(
    path: str,
    name: str,
    size: int,
    *,
    executable: bool,
    shared_lib: bool,
) -> bool:
    if executable or shared_lib:
        return True

    if name in ELECTRON_RUNTIME_NAMES:
        return True

    if name.endswith(RUNTIME_SUFFIXES):
        return True

    if size <= APP_CODE_RESOURCE_MAX and name.endswith(APP_CODE_RESOURCE_SUFFIXES):
        return True

    return False


def is_shared_app_code_path(path: str, name: str, size: int) -> bool:
    return (
        (path.startswith("/usr/share/") or path.startswith("/usr/local/share/"))
        and size <= APP_SHARE_CODE_MAX
        and name.endswith(APP_SHARE_CODE_SUFFIXES)
    )


def should_prune_dir(path: str) -> bool:
    p = os.path.normpath(path).lower()

    # VIP paths must survive pruning, especially Vesktop/Electron cache trees
    # and Flatpak/app payload folders that look like generic browser/app data.
    if is_vip_path(p):
        return False

    if path_has_prefix(p, HARD_COLD_PREFIXES):
        return True

    if (
        is_browser_http_cache_path(p)
        and not is_shader_cache_path(p)
        and not is_targeted_browser_like_cache_path(p)
    ):
        return True

    if path_contains_any(p, PRUNE_DIR_SUBSTRINGS):
        return True

    # Do not scan arbitrary project dependency forests, but keep packaged
    # Electron app runtime node_modules because those can be part of app launch.
    if "/node_modules/" in p and "/resources/app/node_modules/" not in p:
        return True

    return False



def is_hard_cold_file(path: str, name: str, size: int) -> bool:
    if is_vip_path(path):
        return False

    if path_has_prefix(path, HARD_COLD_PREFIXES):
        return True

    if (
        is_browser_http_cache_path(path)
        and not is_shader_cache_path(path)
        and not is_targeted_browser_like_cache_path(path)
    ):
        return True

    if name.endswith(MEDIA_SUFFIXES) and size > 2 * GIB:
        return True

    if name.endswith(DOCUMENT_SUFFIXES) and size > 1 * GIB:
        return True

    if name.endswith(PACKAGE_IMAGE_SUFFIXES) and size > 4 * GIB:
        return True

    if name.endswith(ARCHIVE_SUFFIXES) and not is_app_runtime_path(path) and size > 4 * GIB:
        return True

    # Do not prioritize huge opaque game asset packs, but do not hard-ban
    # normal-sized ones either. On high-RAM desktops, these are valid late
    # fallback candidates after OS/app/runtime files have already been chosen.
    if size > 16 * GIB and name.endswith(GAME_ASSET_SUFFIXES):
        return True

    # Huge monolithic executables/blobs are usually bad.
    # Small/medium runtimes are the win.
    if size > 4 * GIB and name.endswith((".appimage", ".bin")):
        return True

    return False

def classify_file(rec: FileRec) -> tuple[int, int, int]:
    path = os.path.normpath(rec.path).lower()
    name = os.path.basename(path)
    size = rec.size

    vip = vip_classification(path, name, size)
    if vip is not None:
        return vip

    if is_hard_cold_file(path, name, size):
        return (99, 0, 0)

    executable = file_is_executable(rec)
    shared_lib = is_shared_library_name(name)
    steam = is_steam_path(path)
    vr = is_vr_path(path)
    shader = is_shader_cache_path(path)
    browser_profile = is_browser_profile_path(path)
    user_app = path_contains_any(path, USER_APP_SUBSTRINGS)
    sandbox_app_state = is_generic_sandbox_app_state_path(path)
    cosmic = path_contains_any(path, COSMIC_SUBSTRINGS)

    # Targeted bounded caches and game/runtime paths.
    # These are intentionally handled before broad Steam/browser/game logic.

    if is_steam_ui_cache_path(path):
        if size <= STEAM_UI_CACHE_FILE_MAX:
            confidence = 1040
            if "/code cache/" in path:
                confidence += 120
            if "/cache/cache_data/" in path:
                confidence += 100
            if name in {"index", "the-real-index"}:
                confidence += 160
            return (1, confidence, 0)
        return (99, 0, 0)

    if is_firefox_web_cache_path(path):
        if size <= FIREFOX_WEB_CACHE_FILE_MAX:
            confidence = 760
            if "/startupcache/" in path:
                confidence += 160
            if "/cache2/index" in path:
                confidence += 140
            return (3, confidence, 0)
        return (99, 0, 0)

    if is_hytale_world_data_path(path):
        if size <= HYTALE_WORLD_FILE_MAX:
            confidence = 820

            if is_hytale_world_chunk_path(path):
                confidence += 160

            if "/universe/worlds/" in path:
                confidence += 120

            if "/universe/players/" in path:
                confidence += 100

            if name in {
                "config.json",
                "client_metadata.json",
                "permissions.json",
                "whitelist.json",
                "bans.json",
            }:
                confidence += 120

            return (2, confidence, 0)

        return (99, 0, 0)

    if is_hytale_runtime_path(path, name):
        confidence = 980
        if name in {"hytaleserver.jar", "hytaleclient", "hytale-launcher", "libjvm.so"}:
            confidence += 220
        if shared_lib or executable or name.endswith((".jar", ".so")):
            confidence += 140
        return (1, confidence, 0)

    if is_vrchat_content_cache_path(path):
        if size <= VRCHAT_CONTENT_CACHE_FILE_MAX:
            return (2, 840, 0)
        return (99, 0, 0)

    if is_vrchat_runtime_path(path):
        confidence = 930
        if name in {
            "vrchat.exe",
            "unityplayer.dll",
            "gameassembly.dll",
            "start_protected_game.exe",
            "easyanticheat_eos_setup.exe",
            "system.reg",
            "user.reg",
            "userdef.reg",
        }:
            confidence += 240
        if "/easyanticheat/" in path:
            confidence += 220
        if shared_lib or executable or name.endswith((".dll", ".exe")):
            confidence += 180
        if name.endswith(CONFIG_SUFFIXES):
            confidence += 120
        return (1, confidence, 0)

    # Tier 0: core OS/runtime foundation. Keep the proven wins:
    # dynamic linker, system shared libs, core binaries, graphics/audio libs,
    # GTK/Qt/PipeWire/ALSA/Vulkan/Mesa, etc.
    if (
        path_has_prefix(path, HOT_SYSTEM_PREFIXES)
        and (
            shared_lib
            or executable
            or name in HOT_SPECIAL_NAMES
            or name in ELECTRON_RUNTIME_NAMES
            or name.endswith(CONFIG_SUFFIXES)
            or name.endswith(RUNTIME_SUFFIXES)
        )
    ):
        confidence = 900
        if shared_lib:
            confidence += 240
        if executable:
            confidence += 200
        if name in HOT_SPECIAL_NAMES:
            confidence += 260
        if path_contains_any(path, GRAPHICS_AUDIO_RUNTIME_SUBSTRINGS):
            confidence += 160
        if "/obs-" in path or "/obs/" in path or "/obs-plugins/" in path:
            confidence += 240
        if cosmic:
            confidence += 180
        return (0, confidence, 0)

    # Tier 1: Steam / Proton / Wine / selected game / VR launch path.
    # Keep Steam itself, Proton runtimes, VRChat, selected shader caches, and non-Steam VR hot.
    # Do NOT make every Steam game/prefix/shadercache hot just because it lives under steamapps.
    if steam or vr or shader:
        selected_steam_runtime = is_selective_steam_runtime_path(path)
        selected_vrchat_runtime = is_vrchat_runtime_path(path)
        selected_steam_shader = f"/steamapps/shadercache/{VRCHAT_APPID}/" in path
        broad_steam_game_area = path_contains_any(
            path,
            (
                "/steamapps/common/",
                "/steamapps/compatdata/",
                "/steamapps/shadercache/",
            ),
        )

        if name.startswith("appmanifest_") and name.endswith(".acf"):
            # App manifests are small and useful for Steam library startup.
            return (1, 1250, 0)

        if name in STEAM_STARTUP_NAMES:
            # Keep Steam root startup files hot, but do not pull every game's
            # Proton registry into tier 1 unless it is a selected game prefix.
            if "/steamapps/compatdata/" not in path or selected_vrchat_runtime:
                return (1, 1220, 0)

        if path_contains_any(path, STEAM_FAST_SUBSTRINGS):
            confidence = 980
            if shared_lib or executable or name.endswith((".dll", ".exe")):
                confidence += 240
            if name.endswith(CONFIG_SUFFIXES):
                confidence += 180
            if name in ELECTRON_RUNTIME_NAMES:
                confidence += 160
            if name in {"steamwebhelper", "steam", "steam.sh", "proton", "toolmanifest.vdf", "version"}:
                confidence += 220
            return (1, confidence, 0)

        if selected_steam_runtime or selected_vrchat_runtime:
            if shared_lib or executable or name.endswith((".dll", ".exe")):
                return (1, 930, 0)

            if name.endswith(CONFIG_SUFFIXES):
                return (1, 850, 0)

            if size <= 16 * MIB:
                return (2, 560, 0)

            return (5, 120, 0)

        if shader and selected_steam_shader and name.endswith(SHADER_SUFFIXES) and size <= 256 * MIB:
            return (1, 760, 0)

        if shader and not broad_steam_game_area and name.endswith(SHADER_SUFFIXES) and size <= 256 * MIB:
            # Keep global Mesa/NVIDIA shader caches useful, but avoid all Steam game shader caches.
            return (1, 760, 0)

        if vr and not steam:
            # WiVRn / WayVR / Monado / ALVR-style native VR runtimes stay hot.
            if shared_lib or executable or name.endswith((".dll", ".exe")):
                return (1, 900, 0)
            if name.endswith(CONFIG_SUFFIXES):
                return (2, 680, 0)
            if size <= 16 * MIB:
                return (2, 520, 0)

        if broad_steam_game_area:
            # Random game payloads are fallback only. Large opaque packs are
            # especially poor cache value compared with executable/library
            # random reads, so do not lock them at all.
            if name.endswith(GAME_ASSET_SUFFIXES) and size > 256 * MIB:
                return (99, 0, 0)
            return (5, 40, 0)

        return (5, 120, 0)

    # Tier 1: installed application code. Generic native/Flatpak/Snap/Electron
    # code belongs near Steam/VR runtimes because these random reads directly
    # affect launch latency.
    if is_app_runtime_path(path) and is_app_code_resource(
        path,
        name,
        size,
        executable=executable,
        shared_lib=shared_lib,
    ):
        confidence = 940
        if path_has_prefix(path, BROWSER_RUNTIME_PREFIXES):
            confidence += 220
        if path_contains_any(path, ELECTRON_APP_SUBSTRINGS):
            confidence += 180
        if name in ELECTRON_RUNTIME_NAMES:
            confidence += 200
        if shared_lib or executable:
            confidence += 200
        if name.endswith((".so", ".wasm", ".pyc", ".qml", ".js", ".mjs", ".cjs")):
            confidence += 100
        return (1, confidence, 0)

    # Tier 2: code-bearing resources installed under /usr/share. Many modern
    # desktop apps ship JS/QML/Python/typelib/gresource data here.
    if is_shared_app_code_path(path, name, size):
        return (2, 860, 0)

    # Tier 3: browser, Vesktop/Discord, OBS, COSMIC, VS Code, Slack and generic
    # sandboxed-app startup state. Cache databases/config/code, not arbitrary
    # large per-app data.
    # Cache configs and startup DBs, not random HTTP cache blobs.
    if browser_profile or user_app or cosmic or sandbox_app_state:
        if name in BROWSER_STARTUP_NAMES:
            return (3, 900, 0)

        if name in ELECTRON_RUNTIME_NAMES:
            return (3, 880, 0)

        if name.endswith((".sqlite", ".sqlite3", ".db")) and size <= 256 * MIB:
            return (3, 780, 0)

        if name.endswith(CONFIG_SUFFIXES) or name.endswith(RUNTIME_SUFFIXES):
            return (3, 720, 0)

        if (
            size <= 1 * MIB
            and not name.endswith(MEDIA_SUFFIXES)
            and not name.endswith(GAME_ASSET_SUFFIXES)
            and not name.endswith(ARCHIVE_SUFFIXES)
        ):
            return (3, 500, 0)

        return (5, 100, 0)

    # Tier 4: desktop support. Useful for app menus, fonts, icons, file picker,
    # MIME associations, settings apps, and desktop shell startup, but below
    # real binaries/libs/app runtimes.
    if (
        path_has_prefix(path, DESKTOP_SUPPORT_PREFIXES)
        or path_contains_any(path, HOT_USER_SUBSTRINGS)
        or name in HOT_SPECIAL_NAMES
        or name.endswith(FONT_SUFFIXES)
        or name.endswith(ICON_SUFFIXES)
        or name.endswith(".desktop")
    ):
        confidence = 650
        if name in HOT_SPECIAL_NAMES:
            confidence += 240
        if name.endswith(FONT_SUFFIXES):
            confidence += 180
        if name.endswith(".desktop"):
            confidence += 160
        if name.endswith(ICON_SUFFIXES):
            confidence += 80
        if name.endswith(CONFIG_SUFFIXES):
            confidence += 80
        return (4, confidence, 0)

    # Tier 5: fallback. After high-confidence launch/runtime files, fill remaining RAM with
    # smallest safe files first.
    return (5, 0, 0)


def fallback_size_rank(size: int) -> int:
    if size <= 4 * KIB:
        return 0
    if size <= 16 * KIB:
        return 1
    if size <= 64 * KIB:
        return 2
    if size <= 256 * KIB:
        return 3
    if size <= 1 * MIB:
        return 4
    if size <= 4 * MIB:
        return 5
    if size <= 16 * MIB:
        return 6
    if size <= 64 * MIB:
        return 7
    if size <= 256 * MIB:
        return 8
    if size <= 1 * GIB:
        return 9
    return 10


def fallback_content_rank(path: str, name: str) -> int:
    """Keep bulk media/assets behind ordinary small files in fallback cache."""
    if name.endswith(GAME_ASSET_SUFFIXES):
        return 4
    if name.endswith(MEDIA_SUFFIXES):
        return 5
    if name.endswith(DOCUMENT_SUFFIXES):
        return 3
    if name.endswith(ARCHIVE_SUFFIXES):
        return 6
    if name.endswith(PACKAGE_IMAGE_SUFFIXES):
        return 7
    return 0

def cache_budget_caps(cfg: dict) -> dict[str, int]:
    return {
        "steam_htmlcache": parse_size(cfg.get("steam_htmlcache_budget_bytes", "1G")) or GIB,
        "firefox_webcache": parse_size(cfg.get("firefox_webcache_budget_bytes", "2G")) or (2 * GIB),
        "hytale_world": parse_size(cfg.get("hytale_world_budget_bytes", "2G")) or (2 * GIB),
        "vrchat_content_cache": parse_size(cfg.get("vrchat_content_cache_budget_bytes", "2G")) or (2 * GIB),
    }


def cache_budget_file_caps(cfg: dict) -> dict[str, int]:
    # Firefox cache2 entries are individual URL resources, not one file per web
    # page. A recent-resource cap approximates the recent browsing working set
    # without pretending that 50 cache files == 50 pages.
    return {
        "steam_htmlcache": int(cfg.get("steam_htmlcache_max_files", 4000) or 4000),
        "firefox_webcache": int(cfg.get("firefox_webcache_max_files", 2000) or 2000),
    }


def cache_budget_key(rec: FileRec) -> Optional[str]:
    path = os.path.normpath(rec.path).lower()

    if is_steam_ui_cache_path(path):
        return "steam_htmlcache"

    if is_firefox_web_cache_path(path):
        return "firefox_webcache"

    if is_hytale_world_data_path(path):
        return "hytale_world"

    if is_vrchat_content_cache_path(path):
        return "vrchat_content_cache"

    return None


def hytale_save_root(path: str) -> Optional[str]:
    norm = os.path.normpath(path)
    lower = norm.lower()
    marker = "/userdata/saves/"

    idx = lower.find(marker)
    if idx < 0:
        return None

    after = idx + len(marker)
    next_sep = lower.find(os.sep, after)
    if next_sep < 0:
        return None

    return lower[:next_sep]


def dynamic_cache_root_key(rec: FileRec) -> Optional[str]:
    path = os.path.normpath(rec.path).lower()

    if is_hytale_world_data_path(path):
        # Pick one active Hytale save per scan when the file belongs to a save.
        # Shared PrefabCache files do not have a save root, so they are allowed
        # inside the same Hytale world budget without forcing a different save.
        return hytale_save_root(path)

    if is_vrchat_content_cache_path(path):
        # Treat each Cache-WindowsPlayer first-level directory as one content
        # unit. select_files() can then keep whole recent units, skip tiny
        # marker units, and enforce the total 2G cap.
        return vrchat_content_cache_unit_root(path)

    return None

def recency_timestamp_for_path(path: str, st: os.stat_result) -> float:
    lower = os.path.normpath(path).lower()

    if (
        is_firefox_web_cache_path(lower)
        or is_vrchat_content_cache_path(lower)
        or is_hytale_world_data_path(lower)
        or is_steam_ui_cache_path(lower)
    ):
        return max(float(st.st_mtime), float(st.st_atime))

    return float(st.st_mtime)

def _rotational_for_path(path: str) -> Optional[bool]:
    """Best-effort backing-device rotational detection through sysfs."""
    try:
        st = os.stat(path)
        resolved = Path(
            f"/sys/dev/block/{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
        ).resolve(strict=True)
    except (OSError, RuntimeError):
        return None

    candidates = [resolved / "queue/rotational"]
    candidates.extend(parent / "queue/rotational" for parent in resolved.parents)

    for candidate in candidates:
        try:
            value = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value == "0":
            return False
        if value == "1":
            return True

    return None


def resolve_scan_storage_profile(cfg: dict) -> str:
    """Return nonrotational, rotational, mixed, or unknown.

    Backing media does not normally change while the service is running. Cache
    this result so idle status updates never reprobe sysfs/storage.
    """
    roots = tuple(
        os.path.normpath(path)
        for path in cfg.get("include_paths", ["/"])
    )
    cached = _SCAN_STORAGE_PROFILE_CACHE.get(roots)
    if cached is not None:
        return cached

    flags: set[bool] = set()
    seen_devs: set[int] = set()

    for root in roots:
        try:
            dev = os.stat(root).st_dev
        except OSError:
            continue
        if dev in seen_devs:
            continue
        seen_devs.add(dev)

        rotational = _rotational_for_path(root)
        if rotational is not None:
            flags.add(rotational)

    if flags == {False}:
        profile = "nonrotational"
    elif flags == {True}:
        profile = "rotational"
    elif len(flags) > 1:
        profile = "mixed"
    else:
        profile = "unknown"

    _SCAN_STORAGE_PROFILE_CACHE[roots] = profile
    return profile


def resolve_scan_worker_count(cfg: dict) -> int:
    """Choose metadata-I/O concurrency independently from CPU parallelism.

    CPUAffinity/CPUQuota bound actual compute. SSD/NVMe directory walking is
    dominated by metadata waits, so it benefits from more outstanding workers
    than eligible CPUs. Rotational media stays deliberately conservative.
    """
    try:
        allowed_cpus = len(os.sched_getaffinity(0))
    except Exception:
        allowed_cpus = os.cpu_count() or 1

    profile = resolve_scan_storage_profile(cfg)
    max_workers = int(cfg.get("scan_worker_max", 64) or 64)

    if profile == "rotational":
        rotational_max = int(cfg.get("scan_rotational_worker_max", 4) or 4)
        return max(1, min(max_workers, rotational_max))

    if profile == "nonrotational":
        multiplier = float(
            cfg.get("scan_io_worker_multiplier_nonrotational", 3.0) or 3.0
        )
    elif profile == "mixed":
        multiplier = float(
            cfg.get("scan_io_worker_multiplier_mixed", 1.5) or 1.5
        )
    else:
        multiplier = float(
            cfg.get("scan_io_worker_multiplier_unknown", 2.0) or 2.0
        )

    wanted = max(
        1,
        math.ceil(max(1, allowed_cpus) * max(1.0, multiplier)),
    )
    return max(1, min(wanted, max_workers))


def governing_include_root(path: str, include_paths: list[str]) -> Optional[str]:
    matches = [root for root in include_paths if path_is_under(path, root)]
    if not matches:
        return None
    return max(matches, key=len)


def file_record_for_path(
    path: str,
    cfg: dict,
    max_file_size: Optional[int],
    include_paths: Optional[list[str]] = None,
) -> Optional[FileRec]:
    full = os.path.normpath(path)
    excludes = [os.path.normpath(p) for p in cfg["exclude_prefixes"]]

    if path_is_excluded(full, excludes):
        return None

    try:
        st = os.lstat(full)
    except OSError:
        return None

    if not stat.S_ISREG(st.st_mode):
        return None

    include_paths = include_paths or build_include_paths(cfg)
    root = governing_include_root(full, include_paths)
    if root is None:
        return None

    if (
        cfg.get("stay_on_filesystem", True)
        and not root_allows_cross_filesystem(root, cfg)
    ):
        root_dev = safe_dev(root)
        if root_dev is not None and st.st_dev != root_dev:
            return None

    size = st.st_size
    if size <= 0:
        return None

    if max_file_size is not None and size > max_file_size:
        return None

    rec = FileRec(
        path=full,
        size=size,
        mtime=recency_timestamp_for_path(full, st),
        mode=st.st_mode,
    )

    # Do not spend inventory RAM on files the policy can never select.
    if classify_file(rec)[0] >= 99:
        return None

    return rec


def scan_files(
    cfg: dict,
    max_file_size: Optional[int],
    memory_monitor: Optional[MemoryMonitor] = None,
    roots: Optional[list[str]] = None,
) -> list[FileRec]:
    """Parallel scandir walk with storage-aware metadata concurrency.

    CPU affinity/quota still bounds actual compute. On SSD/NVMe we intentionally
    run more metadata workers than eligible CPUs because most worker lifetime is
    spent waiting on filesystem syscalls. Rotational media is conservative.
    """
    include_paths = build_include_paths(cfg)
    scan_roots = include_paths if roots is None else [
        os.path.normpath(p) for p in roots
    ]
    excludes = [os.path.normpath(p) for p in cfg["exclude_prefixes"]]

    work: queue.Queue = queue.Queue()
    files: list[FileRec] = []
    files_lock = threading.Lock()
    abort_event = threading.Event()
    workers = resolve_scan_worker_count(cfg)

    for requested_root in scan_roots:
        if path_is_excluded(requested_root, excludes):
            continue

        governing = governing_include_root(requested_root, include_paths)
        if governing is None:
            continue

        try:
            requested_stat = os.lstat(requested_root)
        except OSError:
            continue

        if stat.S_ISLNK(requested_stat.st_mode):
            continue

        governing_dev = safe_dev(governing)
        if governing_dev is None:
            continue

        stay_on_this_filesystem = (
            cfg.get("stay_on_filesystem", True)
            and not root_allows_cross_filesystem(governing, cfg)
        )

        if stay_on_this_filesystem and requested_stat.st_dev != governing_dev:
            continue

        if stat.S_ISREG(requested_stat.st_mode):
            rec = file_record_for_path(
                requested_root,
                cfg,
                max_file_size,
                include_paths,
            )
            if rec is not None:
                files.append(rec)
            continue

        if not stat.S_ISDIR(requested_stat.st_mode):
            continue

        if should_prune_dir(requested_root):
            continue

        work.put((requested_root, governing_dev, stay_on_this_filesystem))

    def worker() -> None:
        local_files: list[FileRec] = []
        steps = 0

        while True:
            item = work.get()
            if item is None:
                work.task_done()
                break

            dirpath, root_dev, stay_on_this_filesystem = item

            try:
                if abort_event.is_set():
                    continue

                if not RUNNING:
                    abort_event.set()
                    continue

                steps += 1
                if (
                    memory_monitor is not None
                    and steps % int(cfg.get("memory_pressure_abort_check_every", 128) or 128) == 0
                    and memory_monitor.should_abort_scan(cfg)
                ):
                    abort_event.set()
                    continue

                maybe_cooldown(
                    steps,
                    cfg,
                    every_key="scan_cooldown_every",
                    sleep_key="scan_cooldown_seconds",
                    default_every=4096,
                    default_sleep=0.001,
                )

                try:
                    entries = os.scandir(dirpath)
                except OSError:
                    continue

                with entries:
                    for entry in entries:
                        if abort_event.is_set():
                            break

                        steps += 1
                        if (
                            memory_monitor is not None
                            and steps % int(cfg.get("memory_pressure_abort_check_every", 128) or 128) == 0
                            and memory_monitor.should_abort_scan(cfg)
                        ):
                            abort_event.set()
                            break

                        maybe_cooldown(
                            steps,
                            cfg,
                            every_key="scan_cooldown_every",
                            sleep_key="scan_cooldown_seconds",
                            default_every=4096,
                            default_sleep=0.001,
                        )

                        # scandir gives us the child path already. Query d_type
                        # first so normal Linux filesystems avoid unnecessary
                        # stat calls merely to determine entry type.
                        full = entry.path

                        if path_is_excluded(full, excludes):
                            continue

                        try:
                            if entry.is_symlink():
                                continue
                            is_dir = entry.is_dir(follow_symlinks=False)
                            is_file = (
                                False
                                if is_dir
                                else entry.is_file(follow_symlinks=False)
                            )
                        except OSError:
                            continue

                        if is_dir:
                            if should_prune_dir(full.lower()):
                                continue

                            if stay_on_this_filesystem:
                                try:
                                    dir_stat = entry.stat(follow_symlinks=False)
                                except OSError:
                                    continue
                                if dir_stat.st_dev != root_dev:
                                    continue

                            work.put((full, root_dev, stay_on_this_filesystem))
                            continue

                        if not is_file:
                            continue

                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue

                        if stay_on_this_filesystem and st.st_dev != root_dev:
                            continue

                        size = st.st_size
                        if size <= 0:
                            continue

                        if max_file_size is not None and size > max_file_size:
                            continue

                        rec = FileRec(
                            path=full,
                            size=size,
                            mtime=recency_timestamp_for_path(full, st),
                            mode=st.st_mode,
                        )
                        if classify_file(rec)[0] < 99:
                            local_files.append(rec)
            except Exception:
                logging.exception("scan worker error in %s", dirpath)
            finally:
                work.task_done()

        if local_files:
            with files_lock:
                files.extend(local_files)

    threads = [
        threading.Thread(
            target=worker,
            name=f"ramcache-scan-{idx}",
            daemon=True,
        )
        for idx in range(workers)
    ]

    for thread in threads:
        thread.start()

    work.join()

    for _ in threads:
        work.put(None)
    work.join()

    for thread in threads:
        thread.join()

    if abort_event.is_set():
        raise MemoryPressureAbort

    return files


def remove_inventory_prefix(
    inventory: dict[str, FileRec],
    prefix: str,
) -> list[FileRec]:
    prefix = os.path.normpath(prefix)
    prefix_with_sep = prefix + os.sep
    doomed = [
        path
        for path in inventory
        if path == prefix or path.startswith(prefix_with_sep)
    ]

    removed: list[FileRec] = []
    for path in doomed:
        rec = inventory.pop(path, None)
        if rec is not None:
            removed.append(rec)

    return removed


def apply_fs_changes(
    inventory: dict[str, FileRec],
    changes: list[tuple[str, str]],
    cfg: dict,
    max_file_size: Optional[int],
    memory_monitor: Optional[MemoryMonitor],
) -> tuple[list[FileRec], list[FileRec]]:
    """Apply inotify changes without rescanning the whole filesystem."""
    if not changes:
        return [], []

    include_paths = build_include_paths(cfg)
    removed: list[FileRec] = []
    added: list[FileRec] = []
    directory_rescans: set[str] = set()
    file_paths: set[str] = set()

    for events, raw_path in changes:
        path = os.path.normpath(raw_path)
        event_set = {event.strip().upper() for event in events.split(",") if event.strip()}
        is_dir = "ISDIR" in event_set

        if is_dir:
            if "DELETE" in event_set or "MOVED_FROM" in event_set:
                removed.extend(remove_inventory_prefix(inventory, path))
                continue

            if "CREATE" in event_set or "MOVED_TO" in event_set:
                directory_rescans.add(path)
                continue

            # Attribute-only directory changes do not alter file contents.
            continue

        file_paths.add(path)

    # If a parent directory is being rescanned, child paths are covered by it.
    ordered_dirs = sorted(directory_rescans, key=lambda p: (p.count(os.sep), len(p)))
    pruned_dirs: list[str] = []
    for path in ordered_dirs:
        if any(path_is_under(path, parent) for parent in pruned_dirs):
            continue
        pruned_dirs.append(path)

    for directory in pruned_dirs:
        removed.extend(remove_inventory_prefix(inventory, directory))

        if not os.path.isdir(directory):
            continue

        subtree = scan_files(
            cfg,
            max_file_size,
            memory_monitor=memory_monitor,
            roots=[directory],
        )

        for rec in subtree:
            inventory[rec.path] = rec
            added.append(rec)

    for path in file_paths:
        if any(path_is_under(path, directory) for directory in pruned_dirs):
            continue

        old = inventory.pop(path, None)
        if old is not None:
            removed.append(old)

        rec = file_record_for_path(
            path,
            cfg,
            max_file_size,
            include_paths=include_paths,
        )
        if rec is not None:
            inventory[rec.path] = rec
            added.append(rec)

    return removed, added


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


def selection_sort_key(rec: FileRec) -> Optional[tuple]:
    tier, confidence, _ = classify_file(rec)

    if tier >= 99:
        return None

    path = os.path.normpath(rec.path).lower()
    name = os.path.basename(path)
    budget_key = cache_budget_key(rec)
    recency_first = budget_key in RECENCY_FIRST_BUDGET_KEYS

    if tier == 5:
        # Fallback fills leftover RAM only after code/runtime/startup data.
        # Ordinary small files beat photos/audio/video/game packs even when
        # those media files happen to be tiny.
        return (
            tier,
            fallback_content_rank(path, name),
            fallback_size_rank(rec.size),
            rec.size,
            -rec.mtime,
            rec.path,
        )

    if recency_first:
        return (
            tier,
            -confidence,
            -rec.mtime,
            fallback_size_rank(rec.size),
            rec.size,
            rec.path,
        )

    # For real application/runtime tiers, semantic confidence matters more
    # than merely being a tiny file. This makes code/libs/resources outrank
    # low-value small files while still preferring compact files at equal value.
    return (
        tier,
        -confidence,
        fallback_size_rank(rec.size),
        rec.size,
        -rec.mtime,
        rec.path,
    )


def build_selection_index(files) -> list[FileRec]:
    """Build only the ordered record list; do not retain millions of sort tuples."""
    # scan_files()/file_record_for_path() already discard tier-99 records.
    ordered = list(files)
    ordered.sort(key=selection_sort_key)
    return ordered


def build_selection_order(files: list[FileRec]) -> list[FileRec]:
    return build_selection_index(files)


def _ordered_bisect_left(ordered: list[FileRec], key: tuple) -> int:
    lo = 0
    hi = len(ordered)
    while lo < hi:
        mid = (lo + hi) // 2
        mid_key = selection_sort_key(ordered[mid])
        if mid_key is not None and mid_key < key:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _ordered_bisect_right(ordered: list[FileRec], key: tuple) -> int:
    lo = 0
    hi = len(ordered)
    while lo < hi:
        mid = (lo + hi) // 2
        mid_key = selection_sort_key(ordered[mid])
        if mid_key is not None and key < mid_key:
            hi = mid
        else:
            lo = mid + 1
    return lo


def update_selection_index(
    ordered: list[FileRec],
    inventory: dict[str, FileRec],
    removed: list[FileRec],
    added: list[FileRec],
    cfg: dict,
) -> list[FileRec]:
    """Update the global priority order without ever re-sorting the inventory.

    Tiny batches use in-place binary insert/remove. Larger batches remove
    changed paths in one linear pass, binary-search insertion points for only
    the new records, then rebuild the list of references once. This keeps work
    proportional to the change set plus one cheap pointer pass instead of
    repeatedly reclassifying/sorting millions of unchanged files.
    """
    changed_count = len(removed) + len(added)
    if changed_count <= 0:
        return ordered

    small_threshold = int(
        cfg.get("selection_small_update_threshold", 32)
        or 32
    )

    if changed_count <= small_threshold:
        for rec in removed:
            key = selection_sort_key(rec)
            if key is None:
                continue

            idx = _ordered_bisect_left(ordered, key)
            if idx < len(ordered) and selection_sort_key(ordered[idx]) == key:
                ordered.pop(idx)

        for rec in added:
            key = selection_sort_key(rec)
            if key is None:
                continue

            idx = _ordered_bisect_right(ordered, key)
            ordered.insert(idx, rec)

        return ordered

    # Modifications are represented as old-record removal + new-record add.
    # Include added paths in the removal set defensively so a stale duplicate
    # can never survive an unusual watcher sequence.
    changed_paths = {rec.path for rec in removed}
    changed_paths.update(rec.path for rec in added)

    if changed_paths:
        kept = [rec for rec in ordered if rec.path not in changed_paths]
    else:
        kept = list(ordered)

    # Coalesce repeated events for the same path to the newest FileRec.
    added_by_path: dict[str, FileRec] = {}
    for rec in added:
        added_by_path[rec.path] = rec

    placements: list[tuple[int, tuple, FileRec]] = []
    for rec in added_by_path.values():
        key = selection_sort_key(rec)
        if key is None:
            continue
        idx = _ordered_bisect_right(kept, key)
        placements.append((idx, key, rec))

    if not placements:
        return kept

    # Multiple additions may map to the same insertion point; preserve their
    # exact global ordering without sorting the unchanged inventory.
    placements.sort(key=lambda item: (item[0], item[1]))

    merged: list[FileRec] = []
    cursor = 0
    place_idx = 0

    while place_idx < len(placements):
        insert_at = placements[place_idx][0]
        merged.extend(kept[cursor:insert_at])

        while (
            place_idx < len(placements)
            and placements[place_idx][0] == insert_at
        ):
            merged.append(placements[place_idx][2])
            place_idx += 1

        cursor = insert_at

    merged.extend(kept[cursor:])
    return merged


def changes_affect_current_selection(
    current_selected: list[FileRec],
    removed: list[FileRec],
    added: list[FileRec],
) -> bool:
    """Return True only when changed files can alter the currently locked set.

    Most desktop filesystem churn is cache/history/log data that falls below
    the current selection boundary. Keep the inventory accurate, but do not
    rerun the expensive multi-million-file selection pass unless a selected
    file changed/disappeared or a newly changed file outranks the current tail.
    """
    if not removed and not added:
        return False

    if not current_selected:
        return bool(added)

    removed_paths = {rec.path for rec in removed}
    if removed_paths:
        for rec in current_selected:
            if rec.path in removed_paths:
                return True

    boundary_key = selection_sort_key(current_selected[-1])
    if boundary_key is None:
        return True

    for rec in added:
        key = selection_sort_key(rec)
        if key is not None and key <= boundary_key:
            return True

    return False


def select_files(
    ordered: list[FileRec],
    budget_bytes: int,
    cfg: dict,
) -> list[FileRec]:
    if budget_bytes <= 0:
        return []

    selected: list[FileRec] = []
    total = 0
    reserved_total = 0
    steps = 0

    group_caps = cache_budget_caps(cfg)
    group_file_caps = cache_budget_file_caps(cfg)
    group_used: dict[str, int] = {}
    group_file_count: dict[str, int] = {}
    chosen_dynamic_roots: dict[str, str] = {}

    # Precompute VRChat cache unit sizes so the 2G cap is applied to whole
    # recent units, not random individual __data files. This preserves our
    # "newest units first, >=1M each, up to 2G" goal.
    vrchat_unit_sizes: dict[str, int] = {}
    for rec in ordered:
        if cache_budget_key(rec) != "vrchat_content_cache":
            continue

        root_key = dynamic_cache_root_key(rec)
        if root_key is None:
            continue

        vrchat_unit_sizes[root_key] = vrchat_unit_sizes.get(root_key, 0) + rec.size

    vrchat_chosen_units: set[str] = set()
    vrchat_min_unit_bytes = (
        parse_size(cfg.get("vrchat_content_cache_min_unit_bytes", "1M"))
        or MIB
    )

    for rec in ordered:
        steps += 1
        maybe_cooldown(
            steps,
            cfg,
            every_key="select_cooldown_every",
            sleep_key="select_cooldown_seconds",
            default_every=2048,
            default_sleep=0.001,
        )

        budget_key = cache_budget_key(rec)

        if budget_key == "vrchat_content_cache":
            root_key = dynamic_cache_root_key(rec)
            if root_key is None:
                continue

            unit_size = vrchat_unit_sizes.get(root_key, rec.size)
            if unit_size < vrchat_min_unit_bytes:
                continue

            if root_key not in vrchat_chosen_units:
                cap = group_caps.get(budget_key)
                used = group_used.get(budget_key, 0)

                if cap is not None and used + unit_size > cap:
                    continue

                reserved_total = max(reserved_total, total)
                if reserved_total + unit_size > budget_bytes:
                    continue

                vrchat_chosen_units.add(root_key)
                group_used[budget_key] = used + unit_size
                reserved_total += unit_size

        elif budget_key is not None:
            cap = group_caps.get(budget_key)
            used = group_used.get(budget_key, 0)
            file_cap = group_file_caps.get(budget_key)
            used_files = group_file_count.get(budget_key, 0)

            if cap is not None and used + rec.size > cap:
                continue
            if file_cap is not None and used_files >= file_cap:
                continue

            root_key = dynamic_cache_root_key(rec)
            if root_key is not None:
                chosen = chosen_dynamic_roots.get(budget_key)
                if chosen is None:
                    chosen_dynamic_roots[budget_key] = root_key
                elif chosen != root_key:
                    continue

        # The list is priority sorted, not globally size sorted.
        # If one file does not fit, skip it and keep filling with later useful files.
        if total + rec.size > budget_bytes:
            continue

        selected.append(rec)
        total += rec.size

        if budget_key is not None and budget_key != "vrchat_content_cache":
            group_used[budget_key] = group_used.get(budget_key, 0) + rec.size
            group_file_count[budget_key] = group_file_count.get(budget_key, 0) + 1

        if total >= budget_bytes:
            break

    return selected

def bytes_to_gib(n: int) -> float:
    return round(n / GIB, 2)


def choose_target_bytes(
    meminfo: dict[str, int],
    cfg: dict,
    current_target_bytes: Optional[int],
) -> tuple[int, int, int]:
    total = meminfo["MemTotal"]
    available = meminfo["MemAvailable"]
    working_used = total - available

    # vmtouch -l uses mlock(), so Mlocked is the best approximation of
    # how much RAM is currently being held by this cache.
    locked_now = int(meminfo.get("Mlocked", 0))

    floor_available = parse_size(cfg.get("target_available_bytes", "4G")) or (4 * GIB)
    shrink_to_available = (
        parse_size(cfg.get("target_shrink_to_available_bytes", "6G"))
        or (6 * GIB)
    )
    grow_above_available = (
        parse_size(cfg.get("target_grow_above_available_bytes", "7G"))
        or (7 * GIB)
    )
    grow_to_available = (
        parse_size(cfg.get("target_grow_to_available_bytes", "6G"))
        or shrink_to_available
    )

    # Keep the watermarks sane even if the config is edited badly.
    shrink_to_available = max(shrink_to_available, floor_available)
    grow_to_available = max(grow_to_available, shrink_to_available)
    grow_above_available = max(grow_above_available, grow_to_available)

    def target_for_available_reserve(reserve_bytes: int) -> int:
        baseline = int(current_target_bytes) if current_target_bytes is not None else locked_now
        target = baseline + available - reserve_bytes

        selection_budget_cap = parse_size(cfg.get("max_selection_budget_bytes"))
        if selection_budget_cap is None:
            selection_budget_cap = int(
                total * float(cfg.get("max_selection_budget_total_ratio", 4.0))
            )

        return max(0, min(int(target), int(selection_budget_cap)))

    initial_cap = parse_size(cfg.get("target_initial_max_bytes", "4G"))
    grow_step_cap = parse_size(cfg.get("target_max_grow_step_bytes", "2G"))

    configured_max_inflight = parse_size(cfg.get("target_max_inflight_bytes"))

    if configured_max_inflight is not None:
        max_inflight = int(configured_max_inflight)
    elif grow_step_cap is not None and grow_step_cap > 0:
        max_inflight = max(int(grow_step_cap) * 2, int(initial_cap or 0))
    else:
        max_inflight = int(initial_cap or (8 * GIB))

    def cap_growth_to_inflight_limit(target: int) -> int:
        if max_inflight <= 0:
            return target

        if current_target_bytes is None:
            return min(target, locked_now + max_inflight)

        current = int(current_target_bytes)

        if target <= current:
            return target

        already_inflight = max(0, current - locked_now)
        remaining_inflight_room = max(0, max_inflight - already_inflight)

        if remaining_inflight_room <= 0:
            return current

        return min(target, current + remaining_inflight_room)

    if current_target_bytes is None:
        target_bytes = target_for_available_reserve(grow_to_available)

        if initial_cap is not None and initial_cap > 0:
            target_bytes = min(target_bytes, int(initial_cap))

    elif available < floor_available:
        # Memory pressure: shrink immediately and overshoot back to the safer
        # reserve. This avoids bouncing around the hard floor.
        target_bytes = target_for_available_reserve(shrink_to_available)

    elif available > grow_above_available:
        current = int(current_target_bytes)
        target_bytes = target_for_available_reserve(grow_to_available)

        if grow_step_cap is not None and grow_step_cap > 0:
            target_bytes = min(
                target_bytes,
                current + int(grow_step_cap),
            )

        # This is the grow branch. If vmtouch is still catching up, hold the
        # current target. Do not shrink here; real shrinking belongs only in the
        # available < floor_available branch above.
        target_bytes = max(target_bytes, current)

    else:
        # Hysteresis band: do nothing. Keep the existing target.
        target_bytes = int(current_target_bytes)

    target_bytes = cap_growth_to_inflight_limit(int(target_bytes))
    return target_bytes, int(working_used), int(available)

def target_change_is_meaningful(
    current_target_bytes: Optional[int],
    desired_target_bytes: int,
    cfg: dict,
) -> bool:
    if current_target_bytes is None:
        return True

    if desired_target_bytes == current_target_bytes:
        return False

    # Always react immediately when either side is zero.
    if desired_target_bytes == 0 or current_target_bytes == 0:
        return True

    # Shrink immediately. choose_target_bytes() already includes hysteresis, so
    # a shrink request means MemAvailable crossed the hard floor and we need to
    # release cache now.
    if desired_target_bytes < current_target_bytes:
        return True

    # Grow only after choose_target_bytes() says MemAvailable is above the
    # upper watermark. Do not scale the grow deadband with total cache size:
    # on 64G+ systems that strands multiple GiB unused. The absolute deadband
    # is enough to prevent churn while still converging toward the configured reserve.
    abs_deadband = parse_size(cfg.get("target_relock_min_delta", "512M")) or 0
    return desired_target_bytes - current_target_bytes >= abs_deadband

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
        self.lock = threading.Lock()
        self.pending: dict[str, set[str]] = {}
        self.pending_since_monotonic: Optional[float] = None
        self.resync_event = threading.Event()
        self.cfg: dict = {}
        self.include_paths: list[str] = []
        self.mode = "none"
        self.fanotify_disabled = False

    def _write_watch_list(self, cfg: dict) -> None:
        WATCH_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        lines = []

        for p in build_include_paths(cfg):
            lines.append(os.path.normpath(p))

        excluded = {
            os.path.normpath(p)
            for p in cfg["exclude_prefixes"]
        }
        excluded.update(os.path.normpath(p) for p in HARD_COLD_PREFIXES)

        for p in sorted(excluded):
            lines.append("@" + p)

        WATCH_LIST_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _fanotify_roots(self) -> list[str]:
        roots: list[str] = []
        seen_devs: set[int] = set()

        for path in self.include_paths:
            dev = safe_dev(path)
            if dev is None or dev in seen_devs:
                continue
            seen_devs.add(dev)
            roots.append(path)

        return roots

    def _path_allowed(self, path: str) -> bool:
        if not path:
            return False

        path = os.path.normpath(path)
        excludes = [os.path.normpath(p) for p in self.cfg.get("exclude_prefixes", [])]

        if path_is_excluded(path, excludes):
            return False

        if should_prune_dir(path):
            return False

        return any(path_is_under(path, root) for root in self.include_paths)

    def _start_process(self, cmd: list[str], mode: str) -> bool:
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self.mode = mode

        # fanotify setup is essentially immediate. If this binary/kernel
        # combination rejects the request, fall back to recursive inotify.
        time.sleep(0.05)
        return self.proc.poll() is None

    def start(self, cfg: dict) -> None:
        if (
            self.mode == "fanotify-filesystem"
            and self.proc is not None
            and self.proc.poll() is not None
        ):
            self.fanotify_disabled = True

        self.stop()
        self.cfg = dict(cfg)
        self.include_paths = build_include_paths(cfg)
        self._write_watch_list(cfg)
        self.stop_event.clear()

        # Attribute-only events are extremely noisy on active Linux desktops
        # (timestamps/metadata can change without useful cache content changes).
        # Content/path changes remain fully event-driven. Users can explicitly
        # opt back into ATTRIB watching if a workload really needs chmod/chown
        # changes reflected immediately.
        watched_events = ["close_write", "create", "delete", "move"]
        if bool(cfg.get("watch_attribute_events", False)):
            watched_events.append("attrib")
        event_spec = ",".join(watched_events)
        started = False

        fsnotifywait = shutil.which("fsnotifywait")
        if (
            bool(cfg.get("prefer_fanotify_filesystem_watch", True))
            and fsnotifywait
            and not self.fanotify_disabled
        ):
            roots = self._fanotify_roots()
            if roots:
                cmd = [
                    fsnotifywait,
                    "-m",
                    "-q",
                    "-S",
                    "-e",
                    event_spec,
                    "--format",
                    "%e|%w%f",
                    *roots,
                ]
                try:
                    started = self._start_process(cmd, "fanotify-filesystem")
                except Exception:
                    started = False

                if not started:
                    self.fanotify_disabled = True
                    if self.proc is not None:
                        stop_proc(self.proc)
                        self.proc = None

        if not started:
            cmd = [
                "inotifywait",
                "-m",
                "-r",
                "-q",
                "-P",
                "-e",
                event_spec,
                "--format",
                "%e|%w%f",
                "--fromfile",
                str(WATCH_LIST_PATH),
            ]
            self._start_process(cmd, "inotify-recursive")

        with self.lock:
            self.pending.clear()
            self.pending_since_monotonic = None

        def reader() -> None:
            assert self.proc is not None

            try:
                assert self.proc.stdout is not None
                for line in self.proc.stdout:
                    if self.stop_event.is_set():
                        break

                    line = line.rstrip("\n")
                    if not line:
                        continue

                    if "|" not in line:
                        self.resync_event.set()
                        CONTROLLER_WAKE_EVENT.set()
                        continue

                    events, path = line.split("|", 1)
                    event_set = {
                        event.strip().upper()
                        for event in events.split(",")
                        if event.strip()
                    }

                    if "Q_OVERFLOW" in event_set or "UNMOUNT" in event_set:
                        self.resync_event.set()
                        CONTROLLER_WAKE_EVENT.set()
                        continue

                    path = os.path.normpath(path)
                    if not self._path_allowed(path):
                        continue

                    max_pending = int(
                        self.cfg.get("max_pending_fs_events", 100000)
                        or 100000
                    )

                    wake_for_change = False
                    with self.lock:
                        was_empty = not self.pending
                        existing = self.pending.setdefault(path, set())
                        existing.update(event_set)

                        if len(self.pending) > max_pending:
                            # Losing precision is never silently accepted.
                            # Force one recovery scan rather than pretending
                            # the incremental inventory is still authoritative.
                            self.pending.clear()
                            self.pending_since_monotonic = None
                            self.resync_event.set()
                            wake_for_change = True
                        elif was_empty:
                            # Wake once so the controller can arm a long batch
                            # deadline. Further events stay coalesced and do not
                            # repeatedly wake/spin the Python controller.
                            self.pending_since_monotonic = time.monotonic()
                            wake_for_change = True

                    if wake_for_change:
                        CONTROLLER_WAKE_EVENT.set()
            except Exception:
                self.resync_event.set()
                CONTROLLER_WAKE_EVENT.set()
            finally:
                # EOF from a dead watcher is a correctness gap just like an
                # explicit exception. Wake immediately rather than waiting for
                # the idle health heartbeat.
                if not self.stop_event.is_set():
                    self.resync_event.set()
                    CONTROLLER_WAKE_EVENT.set()

        self.thread = threading.Thread(
            target=reader,
            name="ramcache-fs-watcher",
            daemon=True,
        )
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.proc is not None:
            stop_proc(self.proc)
        self.proc = None

        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=1)
        self.thread = None

    def take_changes(self) -> list[tuple[str, str]]:
        with self.lock:
            changes = [
                (",".join(sorted(events)), path)
                for path, events in self.pending.items()
            ]
            self.pending.clear()
            self.pending_since_monotonic = None
        return changes

    def requeue_changes(self, changes: list[tuple[str, str]]) -> None:
        with self.lock:
            was_empty = not self.pending
            for events, path in changes:
                bucket = self.pending.setdefault(path, set())
                bucket.update(
                    event.strip().upper()
                    for event in events.split(",")
                    if event.strip()
                )
            if was_empty and self.pending:
                self.pending_since_monotonic = time.monotonic()

    def pending_count(self) -> int:
        with self.lock:
            return len(self.pending)

    def pending_age_seconds(self) -> float:
        with self.lock:
            if not self.pending or self.pending_since_monotonic is None:
                return 0.0
            return max(0.0, time.monotonic() - self.pending_since_monotonic)

    def needs_resync(self) -> bool:
        return self.resync_event.is_set()

    def mark_resynced(self) -> None:
        self.resync_event.clear()

    def dead(self) -> bool:
        return self.proc is None or self.proc.poll() is not None


def compute_vmtouch_pause_plan(path_count: int, cfg: dict) -> tuple[float, int]:
    pause_seconds = float(cfg.get("vmtouch_feed_pause_seconds", 0.02) or 0.0)
    extra_budget_seconds = float(cfg.get("vmtouch_feed_target_extra_seconds", 30.0) or 0.0)

    if path_count <= 1 or pause_seconds <= 0 or extra_budget_seconds <= 0:
        return 0.0, 0

    pause_count = min(path_count - 1, int(extra_budget_seconds / pause_seconds))
    return pause_seconds, max(0, pause_count)



def start_vmtouch(cfg: dict, max_file_size_bytes: Optional[int], records: list[FileRec]) -> VmtouchRun:
    bytes_locked = sum(r.size for r in records)

    if max_file_size_bytes is not None:
        max_file_size_mib = max(1, (max_file_size_bytes + MIB - 1) // MIB)
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

    pause_seconds, pause_count = compute_vmtouch_pause_plan(len(records), cfg)
    stop_event = threading.Event()

    def feed_paths() -> None:
        first_path = True
        pauses_done = 0
        total_paths = len(records)

        try:
            assert proc.stdin is not None

            for idx, rec in enumerate(records, start=1):
                path = rec.path
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

    return VmtouchRun(
        proc=proc,
        feeder=feeder,
        stop_event=stop_event,
        records=records,
        bytes_locked=bytes_locked,
    )

def selected_bytes(selected: list[FileRec]) -> int:
    return sum(r.size for r in selected)


def run_bytes(runs: list[VmtouchRun]) -> int:
    return sum(r.bytes_locked for r in runs)


def flatten_run_records(runs: list[VmtouchRun]) -> list[FileRec]:
    records: list[FileRec] = []
    for run in runs:
        records.extend(run.records)
    return records


def common_prefix_len(a: list[FileRec], b: list[FileRec]) -> int:
    limit = min(len(a), len(b))
    idx = 0

    while idx < limit and a[idx] == b[idx]:
        idx += 1

    return idx


def stop_vmtouch_runs(runs: list[VmtouchRun]) -> None:
    # Terminate all concurrently for instant RAM release
    for run in runs:
        run.stop_event.set()
        if run.proc.poll() is None:
            try:
                run.proc.terminate()
            except ProcessLookupError:
                pass
                
    for run in reversed(runs):
        stop_proc(run)
    runs.clear()


def urgent_shrink_vmtouch_runs(
    runs: list[VmtouchRun],
    desired_bytes: int,
) -> tuple[list[VmtouchRun], list[FileRec], int]:
    """Unlock enough low-priority chunks immediately and concurrently."""
    before = run_bytes(runs)
    if before <= desired_bytes:
        return runs, flatten_run_records(runs), 0

    to_stop: list[VmtouchRun] = []

    while runs and run_bytes(runs) > desired_bytes:
        to_stop.append(runs.pop())

    # Signal every locker first so multi-GiB releases are parallel rather than
    # serialized one vmtouch process at a time.
    for run in to_stop:
        run.stop_event.set()
        if run.proc.poll() is None:
            try:
                run.proc.terminate()
            except ProcessLookupError:
                pass

    for run in to_stop:
        stop_proc(run)

    after = run_bytes(runs)
    return runs, flatten_run_records(runs), max(0, before - after)


def chunk_selected_records(selected: list[FileRec], cfg: dict) -> list[list[FileRec]]:
    # Smaller chunks make shrink more surgical. The normal profile uses 1G
    # chunks; low-RAM systems use 512M chunks for finer pressure release.
    max_chunk_bytes = (
        parse_size(cfg.get("vmtouch_chunk_target_bytes", "256M"))
        or (256 * MIB)
    )
    max_chunk_paths = int(cfg.get("vmtouch_chunk_max_paths", 4096))

    chunks: list[list[FileRec]] = []
    current: list[FileRec] = []
    current_bytes = 0

    for rec in selected:
        if current and (
            current_bytes + rec.size > max_chunk_bytes
            or len(current) >= max_chunk_paths
        ):
            chunks.append(current)
            current = []
            current_bytes = 0

        current.append(rec)
        current_bytes += rec.size

    if current:
        chunks.append(current)

    return chunks

def maybe_stagger_vmtouch_transition(cfg: dict, key: str) -> None:
    try:
        delay = float(cfg.get(key, 0) or 0.0)
    except (TypeError, ValueError):
        delay = 0.0

    if delay > 0:
        time.sleep(delay)

def start_vmtouch_chunks(
    cfg: dict,
    max_file_size_bytes: Optional[int],
    selected: list[FileRec],
) -> list[VmtouchRun]:
    runs: list[VmtouchRun] = []
    chunks = [chunk for chunk in chunk_selected_records(selected, cfg) if chunk]

    for idx, chunk in enumerate(chunks):
        runs.append(start_vmtouch(cfg, max_file_size_bytes, chunk))

        if idx + 1 < len(chunks):
            maybe_stagger_vmtouch_transition(cfg, "vmtouch_start_stagger_seconds")

    return runs


def sync_vmtouch_cache(
    runs: list[VmtouchRun],
    desired: list[FileRec],
    cfg: dict,
    max_file_size_bytes: Optional[int],
) -> tuple[list[VmtouchRun], list[FileRec]]:
    current = flatten_run_records(runs)

    if current == desired:
        return runs, current

    desired_bytes = selected_bytes(desired)

    # Fast pressure path: stop tail chunks until we are at or below the new
    # budget. We then surgically refill only the desired portion of the final
    # dropped chunk, avoiding the old all-or-nothing cache rebuild.
    to_stop: list[VmtouchRun] = []
    while runs and run_bytes(runs) > desired_bytes:
        to_stop.append(runs.pop())

    for idx, run in enumerate(to_stop):
        run.stop_event.set()

        if run.proc.poll() is None:
            try:
                run.proc.terminate()
            except ProcessLookupError:
                pass

        stop_proc(run)

        if idx + 1 < len(to_stop):
            maybe_stagger_vmtouch_transition(cfg, "vmtouch_stop_stagger_seconds")

    desired_set = set(desired)

    # If a file changed in-place, only recycle chunks that contain a stale
    # record. Unchanged chunks remain locked and are never needlessly rebuilt.
    stale_runs: list[VmtouchRun] = []
    kept_runs: list[VmtouchRun] = []

    for run in runs:
        if all(rec in desired_set for rec in run.records):
            kept_runs.append(run)
        else:
            stale_runs.append(run)

    for idx, run in enumerate(stale_runs):
        run.stop_event.set()

        if run.proc.poll() is None:
            try:
                run.proc.terminate()
            except ProcessLookupError:
                pass

        stop_proc(run)

        if idx + 1 < len(stale_runs):
            maybe_stagger_vmtouch_transition(cfg, "vmtouch_stop_stagger_seconds")

    runs = kept_runs
    del desired_set

    locked_set = set(flatten_run_records(runs))
    missing = [
        rec
        for rec in desired
        if rec not in locked_set
    ]
    del locked_set

    if missing:
        runs.extend(start_vmtouch_chunks(cfg, max_file_size_bytes, missing))

    # Run order is only metadata for future pressure release. The selection
    # sort key already encodes global priority, so sorting chunks by their best
    # member avoids building a huge record->position dictionary.
    def run_priority(run: VmtouchRun) -> tuple:
        best = None
        for rec in run.records:
            key = selection_sort_key(rec)
            if key is not None and (best is None or key < best):
                best = key
        return best if best is not None else (999,)

    runs.sort(key=run_priority)

    return runs, flatten_run_records(runs)


def write_status(
    target_gib: float,
    selected: list[FileRec],
    meminfo: dict[str, int],
    last_scan_epoch: float,
    cfg: dict,
    *,
    last_incremental_scan_epoch: float = 0.0,
    inventory_files: int = 0,
    pending_fs_events: int = 0,
    watcher_mode: str = "none",
    rapid_growth_bytes: int = 0,
    fast_growth_bytes: int = 0,
    psi_some_delta_us: int = 0,
    psi_full_delta_us: int = 0,
    selected_total_bytes: Optional[int] = None,
) -> None:
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    if selected_total_bytes is None:
        selected_total_bytes = sum(r.size for r in selected)
    payload = {
        "controller_version": CONTROLLER_VERSION,
        "timestamp": int(time.time()),
        "memory_profile": cfg.get("memory_profile", "normal"),
        "target_locked_gib": target_gib,
        "selected_files": len(selected),
        "selected_gib": bytes_to_gib(selected_total_bytes),
        "inventory_files": int(inventory_files),
        "memtotal_gib": bytes_to_gib(meminfo["MemTotal"]),
        "memavailable_gib": bytes_to_gib(meminfo["MemAvailable"]),
        "working_used_gib": bytes_to_gib(meminfo["MemTotal"] - meminfo["MemAvailable"]),
        "cached_gib": bytes_to_gib(meminfo.get("Cached", 0)),
        "active_file_gib": bytes_to_gib(meminfo.get("Active(file)", 0)),
        "inactive_file_gib": bytes_to_gib(meminfo.get("Inactive(file)", 0)),
        "mlocked_gib": bytes_to_gib(meminfo.get("Mlocked", 0)),
        "unevictable_gib": bytes_to_gib(meminfo.get("Unevictable", 0)),
        "rapid_memory_growth_gib": bytes_to_gib(rapid_growth_bytes),
        "fast_memory_growth_gib": bytes_to_gib(fast_growth_bytes),
        "psi_memory_some_stall_delta_us": int(psi_some_delta_us),
        "psi_memory_full_stall_delta_us": int(psi_full_delta_us),
        "last_scan_epoch": int(last_scan_epoch),
        "last_incremental_scan_epoch": int(last_incremental_scan_epoch),
        "pending_fs_events": int(pending_fs_events),
        "watcher_mode": watcher_mode,
        "scan_workers": resolve_scan_worker_count(cfg),
        "scan_storage_profile": resolve_scan_storage_profile(cfg),
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    watcher = Watcher()
    memory_monitor = MemoryMonitor()

    current_config_text = None
    watcher_started_once = False
    full_scan_required_reason: Optional[str] = "startup"

    inventory: dict[str, FileRec] = {}
    ordered: list[FileRec] = []

    current_target_bytes: Optional[int] = None
    current_vmtouch_runs: list[VmtouchRun] = []
    current_selected: list[FileRec] = []
    current_locked_bytes = 0

    last_full_scan = 0.0
    last_incremental_scan = 0.0

    while RUNNING:
        try:
            config_text, cfg = load_config()
            config_changed = config_text != current_config_text

            memory_monitor.start(cfg)
            memory_monitor.update_config(cfg)

            watcher_was_dead = watcher.dead()

            if config_changed:
                full_scan_required_reason = (
                    "startup" if current_config_text is None else "configuration changed"
                )

            elif watcher_started_once and watcher_was_dead:
                # A watcher gap can lose events. Reliability wins here: recover
                # with one authoritative scan instead of trusting stale state.
                full_scan_required_reason = "filesystem watcher recovery"

            if config_changed or watcher_was_dead:
                current_config_text = config_text
                watcher.start(cfg)
                watcher_started_once = True

            if watcher.needs_resync():
                full_scan_required_reason = "filesystem event overflow/recovery"

            meminfo = memory_monitor.meminfo()
            max_file_size_bytes = resolve_vmtouch_max_file_size_bytes(meminfo, cfg)

            if not STATUS_PATH.exists():
                write_status(
                    0,
                    [],
                    meminfo,
                    last_full_scan,
                    cfg,
                    last_incremental_scan_epoch=last_incremental_scan,
                    inventory_files=len(inventory),
                    pending_fs_events=watcher.pending_count(),
                    watcher_mode=watcher.mode,
                    rapid_growth_bytes=memory_monitor.recent_growth_bytes(cfg),
                    fast_growth_bytes=memory_monitor.recent_fast_growth_bytes(cfg),
                    psi_some_delta_us=memory_monitor.psi_stall_deltas()[0],
                    psi_full_delta_us=memory_monitor.psi_stall_deltas()[1],
                    selected_total_bytes=0,
                )

            now = time.time()
            full_rescan_interval = int(cfg.get("full_rescan_interval_seconds", 0) or 0)

            if (
                full_rescan_interval > 0
                and last_full_scan > 0
                and now - last_full_scan >= full_rescan_interval
            ):
                full_scan_required_reason = "configured periodic verification"

            # Do not begin expensive discovery work while any of the memory
            # safety signals are already asking us to yield.
            emergency_pressure = memory_monitor.should_abort_scan(cfg)

            inventory_changed = False
            selection_policy_changed = False

            if full_scan_required_reason is not None and not emergency_pressure:
                reason = full_scan_required_reason
                logging.info(
                    "starting full inventory scan (%s) with %d workers",
                    reason,
                    resolve_scan_worker_count(cfg),
                )
                scan_started = time.monotonic()

                # Clear an old overflow marker before scanning. If another
                # overflow happens during the scan it will be set again and
                # force one more recovery pass.
                watcher.mark_resynced()

                try:
                    new_inventory = scan_files(
                        cfg,
                        max_file_size_bytes,
                        memory_monitor=memory_monitor,
                    )

                    if memory_monitor.should_abort_scan(cfg):
                        raise MemoryPressureAbort

                    new_ordered = build_selection_index(new_inventory)
                except MemoryPressureAbort:
                    logging.info(
                        "memory growth/pressure detected during scan; "
                        "aborting scan so cache pressure can be released first"
                    )
                else:
                    inventory = {rec.path: rec for rec in new_inventory}
                    ordered = new_ordered
                    # Drop the temporary scan list reference immediately; the
                    # records now live in inventory/ordered only.
                    del new_inventory
                    last_full_scan = time.time()
                    inventory_changed = True
                    selection_policy_changed = True

                    if watcher.needs_resync():
                        full_scan_required_reason = "filesystem event overflow during scan"
                    else:
                        full_scan_required_reason = None

                    logging.info(
                        "inventory scan complete: %d files in %.2fs",
                        len(inventory),
                        time.monotonic() - scan_started,
                    )

                meminfo = memory_monitor.meminfo()
                max_file_size_bytes = resolve_vmtouch_max_file_size_bytes(meminfo, cfg)

            # Normal filesystem changes are deliberately lazy-batched. The
            # first kernel event wakes us once to arm the deadline; ordinary
            # desktop churn then accumulates for a few minutes. Memory pressure
            # remains independent and immediate.
            incremental_interval = float(
                cfg.get("incremental_rescan_interval_seconds", 180)
                or 180
            )
            incremental_due = (
                full_scan_required_reason is None
                and watcher.pending_count() > 0
                and watcher.pending_age_seconds() >= incremental_interval
            )

            if incremental_due and not emergency_pressure:
                changes = watcher.take_changes()

                try:
                    removed, added = apply_fs_changes(
                        inventory,
                        changes,
                        cfg,
                        max_file_size_bytes,
                        memory_monitor,
                    )
                except MemoryPressureAbort:
                    watcher.requeue_changes(changes)
                    logging.info(
                        "memory growth/pressure detected during incremental scan; "
                        "deferring changed-file refresh"
                    )
                else:
                    if removed or added:
                        # Decide whether the actual locked cache can change
                        # before spending CPU on a full selection pass.
                        affects_locked_selection = (
                            current_target_bytes is None
                            or current_locked_bytes < int(current_target_bytes)
                            or changes_affect_current_selection(
                                current_selected,
                                removed,
                                added,
                            )
                        )

                        ordered = update_selection_index(
                            ordered,
                            inventory,
                            removed,
                            added,
                            cfg,
                        )
                        inventory_changed = True
                        selection_policy_changed = (
                            selection_policy_changed
                            or affects_locked_selection
                        )

                    last_incremental_scan = time.time()
            # Re-sample after any scan work. The memory monitor continues
            # sampling while scans run, so a long scan cannot hide a RAM spike.
            meminfo = memory_monitor.meminfo()
            max_file_size_bytes = resolve_vmtouch_max_file_size_bytes(meminfo, cfg)

            rapid_release_bytes, rapid_growth_bytes = (
                memory_monitor.consume_rapid_release_bytes(cfg)
            )
            psi_release_bytes = memory_monitor.consume_psi_release_bytes(cfg)
            proactive_release_bytes = max(
                rapid_release_bytes,
                psi_release_bytes,
            )

            any_vmtouch_dead = any(
                run.poll() is not None
                for run in current_vmtouch_runs
            )
            active_target_bytes = current_target_bytes

            if not current_vmtouch_runs or any_vmtouch_dead:
                active_target_bytes = None

            desired_target_bytes, _, _ = choose_target_bytes(
                meminfo,
                cfg,
                active_target_bytes,
            )

            # Do not fight an application by immediately growing the cache back
            # while it is still in its loading/allocation burst.
            if (
                memory_monitor.growth_guard_active()
                and current_target_bytes is not None
                and desired_target_bytes > current_target_bytes
            ):
                desired_target_bytes = current_target_bytes

            if proactive_release_bytes > 0 and current_vmtouch_runs:
                locked_estimate = current_locked_bytes
                proactive_target = max(
                    0,
                    locked_estimate - proactive_release_bytes,
                )
                desired_target_bytes = min(
                    desired_target_bytes,
                    proactive_target,
                )

                reasons = []
                if rapid_release_bytes > 0:
                    reasons.append(
                        f"rapid RAM growth {bytes_to_gib(rapid_growth_bytes):.2f} GiB"
                    )
                if psi_release_bytes > 0:
                    reasons.append("kernel PSI memory stall")

                logging.info(
                    "%s; requesting %.2f GiB immediate cache release",
                    " + ".join(reasons) or "memory pressure",
                    bytes_to_gib(proactive_release_bytes),
                )

            urgent_pressure = (
                memory_pressure_active(meminfo, cfg)
                or proactive_release_bytes > 0
            )

            if urgent_pressure:
                memory_monitor.arm_regrow_guard(cfg)

            # Any decision that lowers the cache target uses the same latency-
            # critical concurrent unlock path. Growth is deliberate; shrinkage
            # is always immediate regardless of why the target fell.
            if (
                current_vmtouch_runs
                and desired_target_bytes < current_locked_bytes
            ):
                (
                    current_vmtouch_runs,
                    current_selected,
                    actually_released,
                ) = urgent_shrink_vmtouch_runs(
                    current_vmtouch_runs,
                    desired_target_bytes,
                )

                current_locked_bytes = run_bytes(current_vmtouch_runs)
                current_target_bytes = current_locked_bytes
                desired_target_bytes = current_locked_bytes

                logging.info(
                    "fast cache shrink completed: %.2f GiB unlocked; "
                    "%.2f GiB remains locked",
                    bytes_to_gib(actually_released),
                    bytes_to_gib(current_locked_bytes),
                )

            effective_target_bytes = current_target_bytes
            target_changed = target_change_is_meaningful(
                current_target_bytes,
                desired_target_bytes,
                cfg,
            )

            if target_changed:
                effective_target_bytes = desired_target_bytes

            if effective_target_bytes is None:
                effective_target_bytes = desired_target_bytes
                target_changed = True

            selection_needs_refresh = (
                selection_policy_changed
                or target_changed
                or any_vmtouch_dead
                or not current_selected
                or not current_vmtouch_runs
            )

            # A pressure response is deliberately release-only. Refill can
            # resume after the short regrowth guard expires.
            if urgent_pressure and current_vmtouch_runs:
                selection_needs_refresh = False

            if selection_needs_refresh:
                desired_selected = select_files(
                    ordered,
                    effective_target_bytes,
                    cfg,
                )
                ensure_limits_for_selection(desired_selected, cfg)

                if any_vmtouch_dead:
                    stop_vmtouch_runs(current_vmtouch_runs)

                current_vmtouch_runs, current_selected = sync_vmtouch_cache(
                    current_vmtouch_runs,
                    desired_selected,
                    cfg,
                    max_file_size_bytes,
                )

            current_target_bytes = effective_target_bytes
            current_locked_bytes = run_bytes(current_vmtouch_runs)

            write_status(
                bytes_to_gib(current_locked_bytes),
                current_selected,
                meminfo,
                last_full_scan,
                cfg,
                last_incremental_scan_epoch=last_incremental_scan,
                inventory_files=len(inventory),
                pending_fs_events=watcher.pending_count(),
                watcher_mode=watcher.mode,
                rapid_growth_bytes=memory_monitor.recent_growth_bytes(cfg),
                fast_growth_bytes=memory_monitor.recent_fast_growth_bytes(cfg),
                psi_some_delta_us=memory_monitor.psi_stall_deltas()[0],
                psi_full_delta_us=memory_monitor.psi_stall_deltas()[1],
                selected_total_bytes=current_locked_bytes,
            )

        except Exception:
            logging.exception("controller loop error")

        sleep_for = 300.0
        try:
            _, cfg = load_config()
            sleep_for = float(cfg.get("check_interval_seconds", 300) or 300)

            # A normal filesystem event only wakes us once to establish its
            # batch start time. Do not process it immediately after a long
            # idle period; wait until the batch itself has aged enough.
            if watcher.pending_count() > 0 and full_scan_required_reason is None:
                batch_interval = float(
                    cfg.get("incremental_rescan_interval_seconds", 180)
                    or 180
                )
                due_in = max(
                    0.10,
                    batch_interval - watcher.pending_age_seconds(),
                )
                sleep_for = min(sleep_for, due_in)
        except Exception:
            pass
        if RUNNING:
            # Memory pressure and watcher failures wake immediately. Normal
            # filesystem activity wakes once only to arm its batch deadline;
            # expensive cache/index work stays infrequent and bursty. The long
            # timeout is only a cheap health/config/status heartbeat.
            CONTROLLER_WAKE_EVENT.wait(timeout=max(0.05, sleep_for))
            CONTROLLER_WAKE_EVENT.clear()

    memory_monitor.stop()
    watcher.stop()
    stop_vmtouch_runs(current_vmtouch_runs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
  chmod 755 /opt/ramcache-controller/ramcache_controller.py
}

write_config() {
  install -d -m 755 /etc/ramcache-controller

  cat > /etc/ramcache-controller/config.json <<'JSON'
{
  "include_paths": ["/", "/home"],
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
  "auto_include_common_app_paths": true,
  "cross_filesystem_include_roots": ["/snap"],

  "check_interval_seconds": 600,
  "incremental_rescan_interval_seconds": 600,
  "full_rescan_interval_seconds": 0,
  "prefer_fanotify_filesystem_watch": true,
  "watch_attribute_events": false,
  "max_pending_fs_events": 350000,

  "scan_worker_max": 96,
  "scan_io_worker_multiplier_nonrotational": 6.0,
  "scan_io_worker_multiplier_mixed": 2,
  "scan_io_worker_multiplier_unknown": 3.0,
  "scan_rotational_worker_max": 4,
  "scan_cooldown_every": 0,
  "scan_cooldown_seconds": 0.0,
  "select_cooldown_every": 0,
  "select_cooldown_seconds": 0.0,
  "selection_small_update_threshold": 32,

  "memory_monitor_interval_seconds": 0.50,
  "fast_memory_growth_window_seconds": 10,
  "fast_memory_growth_threshold_bytes": "1G",
  "fast_memory_growth_min_unacked_bytes": "512M",
  "rapid_memory_window_seconds": 60,
  "rapid_memory_growth_threshold_bytes": "2G",
  "rapid_memory_release_multiplier": 1.0,
  "rapid_memory_release_margin_bytes": "512M",
  "rapid_memory_prediction_seconds": 5,
  "rapid_memory_max_release_bytes": "6G",
  "memory_pressure_regrow_cooldown_seconds": 30,
  "psi_memory_some_stall_threshold_us": 100000,
  "psi_memory_full_stall_threshold_us": 20000,
  "psi_memory_release_bytes": "2G",
  "memory_pressure_abort_check_every": 64,

  "target_available_bytes": "4G",
  "target_shrink_to_available_bytes": "6G",
  "target_grow_above_available_bytes": "7G",
  "target_grow_to_available_bytes": "6G",

  "target_initial_max_bytes": "8G",
  "target_max_grow_step_bytes": "8G",
  "target_max_inflight_bytes": "8G",

  "vmtouch_chunk_target_bytes": "1024M",
  "vmtouch_chunk_max_paths": 8192,
  "max_selection_budget_total_ratio": 4.0,

  "steam_htmlcache_budget_bytes": "1G",
  "steam_htmlcache_max_files": 4000,
  "firefox_webcache_budget_bytes": "2G",
  "firefox_webcache_max_files": 2000,
  "hytale_world_budget_bytes": "2G",
  "vrchat_content_cache_budget_bytes": "2G",

  "target_relock_min_delta": "1G",
  "target_relock_min_delta_ratio": 0.07,

  "fd_limit_reserve": 65536,
  "fd_limit_auto_max": 8388608,
  "memlock_limit_reserve": "1G",
  "memlock_limit_min": "1G",

  "vmtouch_max_file_size": "128G",
  "vmtouch_feed_pause_seconds": 0.002,
  "vmtouch_feed_target_extra_seconds": 1,
  "vmtouch_start_stagger_seconds": 0.05,
  "vmtouch_stop_stagger_seconds": 0.02,

  "low_ram_profile_enabled": true,
  "low_ram_total_threshold_bytes": "20G",
  "low_ram_profile_overrides": {}
}
JSON
}

cpu_quota_for_thread_ratio() {
  local ratio="${1:-0.25}"

  python3 - "$ratio" <<'PY'
import math
import os
import sys

ratio = float(sys.argv[1])

try:
    threads = len(os.sched_getaffinity(0))
except Exception:
    threads = os.cpu_count() or 1

# systemd CPUQuota is measured as a percentage of one logical CPU.
# 24 logical CPUs * 25% = 600%, i.e. six CPU-cores worth of aggregate time.
quota = max(1, math.floor(max(1, threads) * ratio * 100))
print(f"{quota}%")
PY
}

cpu_affinity_for_thread_ratio() {
  local ratio="${1:-0.50}"

  python3 - "$ratio" <<'PY'
import math
import os
import sys
from pathlib import Path

ratio = float(sys.argv[1])

try:
    cpus = sorted(os.sched_getaffinity(0))
except Exception:
    cpus = list(range(os.cpu_count() or 1))

target = max(1, math.ceil(len(cpus) * ratio))

def topology_key(cpu):
    base = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
    try:
        package = (base / "physical_package_id").read_text().strip()
        core = (base / "core_id").read_text().strip()
        return (package, core)
    except Exception:
        return ("cpu", str(cpu))

# Prefer one SMT sibling from each physical core first. On a 12C/24T 3900X,
# this normally chooses 12 logical CPUs spanning all 12 physical cores.
chosen = []
seen_cores = set()

for cpu in cpus:
    key = topology_key(cpu)
    if key in seen_cores:
        continue
    seen_cores.add(key)
    chosen.append(cpu)
    if len(chosen) >= target:
        break

if len(chosen) < target:
    chosen_set = set(chosen)
    for cpu in cpus:
        if cpu in chosen_set:
            continue
        chosen.append(cpu)
        if len(chosen) >= target:
            break

print(" ".join(str(cpu) for cpu in chosen[:target]))
PY
}

write_service() {
  local cpu_quota
  local cpu_affinity

  cpu_quota="$(cpu_quota_for_thread_ratio 0.25)"
  cpu_affinity="$(cpu_affinity_for_thread_ratio 0.50)"

  cat > /etc/systemd/system/ramcache-controller.service <<UNIT
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
RestartSec=5
KillMode=control-group

# Execute only on half of the machine's logical CPUs, preferring one SMT
# sibling per physical core, while capping aggregate CPU time to 25% of the
# whole machine. Metadata scanning may use more *threads* than eligible CPUs
# because most are blocked on storage syscalls; the quota still caps compute.
# Example on a 24-thread CPU: 12 eligible CPUs, 600% aggregate quota.
CPUAccounting=true
CPUAffinity=$cpu_affinity
CPUQuota=$cpu_quota
CPUQuotaPeriodSec=20ms

# Foreground/user work wins scheduling and I/O contention.
Nice=19
IOSchedulingClass=idle

LimitNOFILE=infinity
LimitMEMLOCK=infinity
RuntimeDirectory=ramcache-controller

[Install]
WantedBy=multi-user.target
UNIT
}

write_sysctls() {
  cat > /etc/sysctl.d/99-ramcache-inotify.conf <<'EOF'
fs.inotify.max_user_watches=1048576
fs.inotify.max_user_instances=1024
fs.inotify.max_queued_events=262144
EOF

  # Own a dedicated VM sysctl file. Linux 6.16+ exposes
  # vfs_cache_pressure_denom; older Mint/Ubuntu/Pop kernels do not. Never write
  # an unsupported key, so installation and boot stay clean on either kernel.
  {
    echo 'vm.vfs_cache_pressure=10'
    if [[ -e /proc/sys/vm/vfs_cache_pressure_denom ]]; then
      echo 'vm.vfs_cache_pressure_denom=100'
    fi
  } > /etc/sysctl.d/99-ramcache-vm.conf

  # v1.2 could have created this exact legacy file. Remove it only when it is
  # clearly ours; never overwrite/delete a user's unrelated tuning file.
  legacy=/etc/sysctl.d/99-cache-aggressive.conf
  if [[ -f "$legacy" ]]; then
    legacy_compact="$(grep -Ev '^[[:space:]]*(#|$)' "$legacy" | tr -d '[:space:]' || true)"
    if [[ "$legacy_compact" == 'vm.vfs_cache_pressure=10vm.vfs_cache_pressure_denom=100' ]]; then
      rm -f "$legacy"
    fi
  fi

  # Apply only files owned by this installer. This avoids failing installation
  # because some unrelated sysctl file elsewhere on the machine is invalid.
  sysctl -p /etc/sysctl.d/99-ramcache-inotify.conf >/dev/null
  sysctl -p /etc/sysctl.d/99-ramcache-vm.conf >/dev/null
}

ensure_dependencies() {
  local packages=()

  command -v python3 >/dev/null 2>&1 || packages+=(python3)
  command -v vmtouch >/dev/null 2>&1 || packages+=(vmtouch)
  command -v inotifywait >/dev/null 2>&1 || packages+=(inotify-tools)

  if ((${#packages[@]})); then
    if ! command -v apt-get >/dev/null 2>&1; then
      echo "ERROR: This installer expects an Ubuntu/Debian-family system with apt (Ubuntu, Pop!_OS, Linux Mint)." >&2
      return 1
    fi

    echo "Installing required packages: ${packages[*]}"
    apt-get update
    apt-get install -y "${packages[@]}"
  fi
}

fsnotifywait_has_filesystem_option() {
  # IMPORTANT: fsnotifywait --help intentionally exits non-zero upstream.
  # Capture its text first instead of piping it under `set -o pipefail`,
  # otherwise a perfectly valid --filesystem/-S option is reported missing.
  local help_text
  command -v fsnotifywait >/dev/null 2>&1 || return 1
  help_text="$(fsnotifywait --help 2>&1 || true)"
  grep -q -- '--filesystem' <<<"$help_text"
}

probe_fanotify_filesystem_watch() {
  # Test the real capability, not just whether the binary advertises -S.
  # fsnotifywait exit codes:
  #   0 = a requested event occurred (watch worked)
  #   2 = timeout with no event (watch also worked)
  #   1 = setup/runtime error (unsupported, denied, etc.)
  #
  # Installation runs as root, which is required for fanotify on modern
  # kernels. /tmp is only used to identify a mounted filesystem; -S places a
  # filesystem mark rather than recursively creating one watch per directory.
  local rc
  command -v fsnotifywait >/dev/null 2>&1 || return 1
  fsnotifywait_has_filesystem_option || return 1

  set +e
  fsnotifywait -q -S -t 1 -e create /tmp >/dev/null 2>&1
  rc=$?
  set -e

  [[ "$rc" -eq 0 || "$rc" -eq 2 ]]
}

ensure_fs_watch_tools() {
  # inotifywait is the reliable baseline. fsnotifywait/fanotify is optional
  # and preferred automatically when the installed inotify-tools build and
  # running kernel support it.
  if ! command -v inotifywait >/dev/null 2>&1; then
    echo "Installing Linux filesystem notification tools (inotify-tools)..."
    apt-get update
    apt-get install -y inotify-tools
  fi

  if ! command -v inotifywait >/dev/null 2>&1; then
    echo "ERROR: inotifywait is unavailable even after installing inotify-tools." >&2
    return 1
  fi

  if probe_fanotify_filesystem_watch; then
    echo "Filesystem watcher: fanotify filesystem mode (-S) verified working; it will be preferred."
  elif fsnotifywait_has_filesystem_option; then
    echo "Filesystem watcher: fsnotifywait supports fanotify -S, but the runtime probe failed; recursive inotify will be the safe fallback."
  elif command -v fsnotifywait >/dev/null 2>&1; then
    echo "Filesystem watcher: fsnotifywait is installed but this build does not expose -S/--filesystem; recursive inotify will be used."
  else
    echo "Filesystem watcher: fsnotifywait is not installed; recursive inotify will be used."
  fi
}

install_all() {
  need_root
  export DEBIAN_FRONTEND=noninteractive
  ensure_dependencies
  ensure_fs_watch_tools
  write_controller
  write_config
  write_service
  write_sysctls
  systemctl daemon-reload
  systemctl enable ramcache-controller.service
  # Always restart on install/upgrade so the running Python process actually
  # loads the newly written controller instead of continuing old in-memory code.
  systemctl restart ramcache-controller.service

  echo
  echo "Installed RAM cache controller v1.3.2."
  echo "Status:"
  echo "  systemctl status ramcache-controller.service --no-pager"
  echo "  python3 -m json.tool /run/ramcache-controller/status.json"
}

uninstall_all() {
  need_root

  systemctl stop ramcache-controller.service || true
  systemctl kill ramcache-controller.service --kill-who=all || true
  systemctl disable ramcache-controller.service || true

  rm -f /etc/systemd/system/ramcache-controller.service
  rm -rf /opt/ramcache-controller
  rm -rf /etc/ramcache-controller
  rm -rf /run/ramcache-controller
  rm -f /etc/sysctl.d/99-ramcache-inotify.conf
  rm -f /etc/sysctl.d/99-ramcache-vm.conf

  legacy=/etc/sysctl.d/99-cache-aggressive.conf
  if [[ -f "$legacy" ]]; then
    legacy_compact="$(grep -Ev '^[[:space:]]*(#|$)' "$legacy" | tr -d '[:space:]' || true)"
    if [[ "$legacy_compact" == 'vm.vfs_cache_pressure=10vm.vfs_cache_pressure_denom=100' ]]; then
      rm -f "$legacy"
    fi
  fi

  systemctl daemon-reload
  systemctl reset-failed ramcache-controller.service || true

  echo
  echo "Removed ramcache-controller."
  echo "Removed:"
  echo "  /etc/ramcache-controller"
  echo "  /opt/ramcache-controller"
  echo "  /run/ramcache-controller"
  echo "  /etc/systemd/system/ramcache-controller.service"
  echo "  /etc/sysctl.d/99-ramcache-inotify.conf"
  echo "  /etc/sysctl.d/99-ramcache-vm.conf"
}

status_all() {
  echo "RAM cache controller installer: v1.3.2"
  if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    echo "Distribution: ${PRETTY_NAME:-${ID:-Linux}}"
  fi
  echo "Kernel: $(uname -r)"
  systemctl status ramcache-controller.service --no-pager || true
  echo
  if [[ -f /run/ramcache-controller/status.json ]]; then
    python3 -m json.tool /run/ramcache-controller/status.json || cat /run/ramcache-controller/status.json
  else
    echo "No status file yet."
  fi
  echo
  grep -E 'MemAvailable|Cached|Active\(file\)|Inactive\(file\)|Mlocked|Unevictable' /proc/meminfo || true

  echo
  echo "VM cache tuning:"
  echo "  vm.vfs_cache_pressure: $(cat /proc/sys/vm/vfs_cache_pressure 2>/dev/null || echo unavailable)"
  if [[ -e /proc/sys/vm/vfs_cache_pressure_denom ]]; then
    echo "  vm.vfs_cache_pressure_denom: supported"
  else
    echo "  vm.vfs_cache_pressure_denom: not exposed by this kernel (safely skipped)"
  fi

  echo
  echo "Filesystem watcher capabilities:"
  if command -v inotifywait >/dev/null 2>&1; then
    echo "  inotifywait:  $(command -v inotifywait)"
  else
    echo "  inotifywait:  missing"
  fi

  if command -v fsnotifywait >/dev/null 2>&1; then
    echo "  fsnotifywait: $(command -v fsnotifywait)"
    if fsnotifywait_has_filesystem_option; then
      echo "  fanotify filesystem option (-S): advertised by userspace tool"
      if [[ "$(id -u)" -eq 0 ]]; then
        if probe_fanotify_filesystem_watch; then
          echo "  fanotify filesystem runtime probe: PASS"
        else
          echo "  fanotify filesystem runtime probe: FAIL (controller will fall back safely)"
        fi
      else
        echo "  fanotify filesystem runtime probe: skipped (run status with sudo for privileged probe)"
      fi
    else
      echo "  fanotify filesystem option (-S): not supported by this fsnotifywait build"
    fi
  else
    echo "  fsnotifywait: missing (controller will use recursive inotify)"
  fi

  kernel_config="/boot/config-$(uname -r)"
  if [[ -r "$kernel_config" ]]; then
    if grep -q '^CONFIG_FANOTIFY=y' "$kernel_config"; then
      echo "  kernel CONFIG_FANOTIFY: enabled"
    else
      echo "  kernel CONFIG_FANOTIFY: not reported as enabled"
    fi
  else
    echo "  kernel CONFIG_FANOTIFY: config file unavailable; runtime watcher result is authoritative"
  fi

  if [[ -f /run/ramcache-controller/status.json ]]; then
    python3 - <<'PY' 2>/dev/null || true
import json
from pathlib import Path

try:
    data = json.loads(Path("/run/ramcache-controller/status.json").read_text())
    mode = data.get("watcher_mode", "unknown")
    print(f"  active controller watcher: {mode}")
except Exception:
    pass
PY
  fi
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
