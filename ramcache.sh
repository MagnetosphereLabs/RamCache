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
  STAGED_CONTROLLER=$(mktemp /opt/ramcache-controller/.controller.XXXXXX)
  local staged_controller="$STAGED_CONTROLLER"
  cat > "$staged_controller" <<'PY' 
#!/usr/bin/env python3
import json
import argparse
import concurrent.futures
import ctypes
import errno
import fcntl
import hashlib
import multiprocessing
import pwd
import select
import shlex
import sqlite3
import struct
import sys
import tempfile
import uuid
import logging
import math
import os
import queue
import re
import resource
import shutil
import signal
import stat
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
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
CONTROLLER_VERSION = "1.4.0"
STATE_PATH = Path("/var/lib/ramcache-controller")
RUNTIME_PATH = Path("/run/ramcache-controller")
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
POLICY_VERSION = 2
_SCAN_STORAGE_PROFILE_CACHE: dict[tuple[str, ...], str] = {}

@dataclass(frozen=True, slots=True)
class FileRec:
    path: str
    size: int
    mtime: float
    mode: int
    dev: int = 0
    ino: int = 0
    mtime_ns: int = 0
    ctime_ns: int = 0
    priority: tuple = field(default=(), compare=False)
    budget: str = field(default="", compare=False)


def handle_signal(signum, frame):
    global RUNNING
    RUNNING = False
    CONTROLLER_WAKE_EVENT.set()


def load_config() -> tuple[str, dict]:
    raw = CONFIG_PATH.read_text(encoding="utf-8")
    cfg = json.loads(raw)
    if not isinstance(cfg, dict):
        raise ValueError("configuration must be a JSON object")
    validate_config(cfg)
    effective = apply_memory_size_profile(cfg)
    validate_config(effective)
    return raw, effective


def validate_config(cfg: dict) -> None:
    for key in ("include_paths", "exclude_prefixes", "cross_filesystem_include_roots"):
        value = cfg.get(key, ["/"] if key == "include_paths" else [])
        if not isinstance(value, list) or any(not isinstance(p, str) or not p.startswith("/") or "\0" in p for p in value):
            raise ValueError(key + " must contain absolute paths")
        cfg[key] = value
    counts = {"scan_worker_max", "metadata_worker_cap", "classification_worker_max",
              "warming_worker_max", "scan_rotational_worker_max", "vmtouch_chunk_max_paths",
              "plan_max_files", "learning_pending_max", "learning_max_files", "max_pending_fs_events"}
    flags = {"learning_enabled", "learn_file_opens", "adaptive_memory_reserve", "stay_on_filesystem",
             "auto_include_common_app_paths", "prefer_fanotify_filesystem_watch",
             "watch_attribute_events", "low_ram_profile_enabled"}
    for key, value in list(cfg.items()):
        if (key.endswith("_bytes") or key in {"vmtouch_max_file_size", "target_relock_min_delta"}) and value is not None:
            if isinstance(value, bool) or parse_size(value) < 0:
                raise ValueError(key + " cannot be negative")
        if key.endswith("_seconds") or "_multiplier" in key or key.endswith("_ratio"):
            number = float(value)
            if isinstance(value, bool) or not math.isfinite(number) or number < 0:
                raise ValueError(key + " must be a finite nonnegative number")
            cfg[key] = number
        if key in counts or key.endswith("_max_files") or key.endswith("_threshold_us"):
            number = float(value)
            if isinstance(value, bool) or not math.isfinite(number) or not number.is_integer() or number < (1 if key in counts else 0):
                raise ValueError(key + " must be a valid nonnegative integer (worker counts must be positive)")
            cfg[key] = int(number)
        if key in flags and not isinstance(value, bool):
            raise ValueError(key + " must be true or false")
    overrides = cfg.get("low_ram_profile_overrides", {})
    if not isinstance(overrides, dict) or "low_ram_profile_overrides" in overrides:
        raise ValueError("low_ram_profile_overrides must be a non-nested JSON object")
    if overrides:
        validate_config({**cfg, **overrides, "low_ram_profile_overrides": {}})
    binary = cfg.get("vmtouch_binary")
    if binary is not None and (not isinstance(binary, str) or not os.path.isabs(binary) or "\0" in binary):
        raise ValueError("vmtouch_binary must be an absolute executable path")


def parse_size(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ValueError("size must be finite")
        return int(value)
    match = re.fullmatch(r"\s*([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*([KMGTPE]?)(?:I?B)?\s*", str(value).upper())
    if not match:
        raise ValueError("invalid byte size: " + str(value))
    power = " KMGTPE".index(match.group(2)) if match.group(2) else 0
    return int(float(match.group(1)) * (1024 ** power))


def parse_meminfo() -> dict[str, int]:
    data: dict[str, int] = {}
    with open("/proc/meminfo", "r", encoding="utf-8") as f:
        for line in f:
            name, value = line.split(":", 1)
            data[name] = int(value.strip().split()[0]) * KIB
    data["PhysicalMemTotal"] = data["MemTotal"]
    # Respect service/container limits as well as physical RAM. Locking memory
    # against the host's apparent free RAM can otherwise trigger a cgroup OOM.
    try:
        root = Path("/sys/fs/cgroup")
        current = root
        with open("/proc/self/cgroup", encoding="utf-8") as source:
            for line in source:
                if line.startswith("0::"):
                    candidate = root / line.strip().split("::", 1)[1].lstrip("/")
                    if candidate.is_dir():
                        current = candidate
                    break
        while current == root or root in current.parents:
            used = read_int_file(str(current / "memory.current"))
            for name in ("memory.max", "memory.high"):
                limit = read_int_file(str(current / name))
                if used is not None and limit is not None and 0 < limit < data["PhysicalMemTotal"]:
                    data["MemTotal"] = min(data["MemTotal"], limit)
                    data["MemAvailable"] = min(data["MemAvailable"], max(0, limit - used))
            if current == root:
                break
            current = current.parent
    except OSError:
        pass
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
    "vmtouch_chunk_target_bytes": "128M",
    "vmtouch_chunk_max_paths": 4096,

    # React quickly to smaller changes.
    "target_relock_min_delta": "256M",

    "steam_htmlcache_budget_bytes": "768M",
    "steam_htmlcache_max_files": 16384,
    "firefox_webcache_budget_bytes": "1G",
    "firefox_webcache_max_files": 32768,
    "chromium_webcache_budget_bytes": "1G",
    "chromium_webcache_max_files": 32768,
    "electron_webcache_budget_bytes": "512M",
    "electron_webcache_max_files": 16384,
    "desktop_shader_cache_budget_bytes": "256M",
    "desktop_shader_cache_max_files": 8192,
    "desktop_compiled_cache_budget_bytes": "64M",
    "desktop_compiled_cache_max_files": 8192,
    "app_catalog_budget_bytes": "64M",
    "app_catalog_max_files": 4096,
    "hytale_world_budget_bytes": "1G",
    "vrchat_content_cache_budget_bytes": "1G",

    # Avoid giant single files on low-DRAM systems.
    "vmtouch_max_file_size": "2G",

    "vmtouch_feed_pause_seconds": 0.005,
    "vmtouch_feed_target_extra_seconds": 5,

    "scan_worker_max": 4,
    "classification_worker_max": 2,
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
    homes = {"/root"}
    try:
        for entry in pwd.getpwall():
            if entry.pw_uid >= 1000 and entry.pw_uid < 65534 and entry.pw_dir.startswith("/"):
                if entry.pw_dir not in ("/", "/nonexistent") and os.path.isdir(entry.pw_dir):
                    homes.add(os.path.normpath(entry.pw_dir))
    except OSError:
        pass
    try:
        homes.update(str(p) for p in Path("/home").iterdir() if p.is_dir())
    except OSError:
        pass
    return [Path(p) for p in sorted(homes)]


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
        Path("/usr"),
        Path("/etc"),
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

    for p in APP_CATALOG_PREFIXES + (
        "/var/lib/dpkg", "/var/lib/pacman/local", "/var/lib/rpm", "/var/cache/fontconfig",
    ):
        add(Path(p))

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

            # Shared desktop caches; browser caches are bounded separately.
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

        for relative in (
            ".config/mozilla/firefox", ".cache/mozilla/firefox", ".cache/firefox",
            ".librewolf", ".zen", ".floorp", ".waterfox",
            ".config/librewolf", ".config/zen", ".config/floorp", ".config/waterfox",
            ".cache/librewolf", ".cache/zen", ".cache/floorp", ".cache/waterfox",
            ".config/google-chrome-beta", ".config/google-chrome-unstable",
            ".config/microsoft-edge", ".config/microsoft-edge-beta", ".config/microsoft-edge-dev",
            ".cache/google-chrome", ".cache/google-chrome-beta", ".cache/google-chrome-unstable",
            ".cache/chromium", ".cache/chromium-browser", ".cache/BraveSoftware",
            ".cache/microsoft-edge", ".cache/microsoft-edge-beta", ".cache/microsoft-edge-dev",
            ".cache/vivaldi", ".cache/opera",
            ".cache/mesa_shader_cache_db", ".cache/mesa_shader_cache_sf", ".nv/GLCache",
            ".cache/gstreamer-1.0", ".cache/plasmashell", ".cache/kwin",
            ".local/share/gnome-shell/extensions", ".local/share/cinnamon",
            ".local/share/plasma", ".local/share/kwin", ".local/share/pop-launcher",
            ".local/share/nemo", ".local/share/nautilus/scripts", ".local/share/themes",
            ".config/hypr", ".config/sway", ".config/niri", ".config/waybar",
            ".config/pipewire", ".config/wireplumber",
        ):
            add(home / relative)

        for app_id in (
            "org.mozilla.firefox", "io.gitlab.librewolf-community", "app.zen_browser.zen",
            "one.ablaze.floorp", "org.chromium.Chromium", "com.google.Chrome",
            "com.brave.Browser", "com.microsoft.Edge", "com.vivaldi.Vivaldi",
            "com.discordapp.Discord", "dev.vencord.Vesktop",
        ):
            add(home / ".var/app" / app_id)

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
    cross_roots = cfg.get("_cross_roots_resolved")
    if cross_roots is None:
        cross_roots = tuple({variant for p in cfg.get("cross_filesystem_include_roots", ["/snap"])
                             for variant in (os.path.normpath(p), os.path.realpath(p))})
        cfg["_cross_roots_resolved"] = cross_roots
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

    # A /snap directory often shares the root device while its mounted app
    # revisions do not. Keep explicit cross-filesystem roots and their mounts;
    # otherwise same-device deduplication silently hides every Snap payload.
    cross_roots = [os.path.realpath(p) for p in raw_paths if root_allows_cross_filesystem(p, cfg)]
    if cross_roots:
        try:
            with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as source:
                for line in source:
                    fields = line.split()
                    if len(fields) > 4:
                        mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
                        if any(path_is_under(mount, root) for root in cross_roots) and mount not in raw_paths:
                            raw_paths.append(mount)
        except OSError:
            pass

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

            if root_allows_cross_filesystem(path, cfg):
                # Keep nested mounts explicit for fanotify's per-filesystem
                # marks, even when the directory walker may reach them too.
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
    "/opencomposite",
    "/wlx-overlay-s",
    "/wlxoverlay",
)

SHADER_CACHE_SUBSTRINGS = (
    "/mesa_shader_cache/",
    "/steamapps/shadercache/",
    "/shadercache/",
    "/glcache/",
    "/.nv/glcache/",
    "/.cache/nvidia/",
    "/.cache/mesa_shader_cache/",
    "/mesa_shader_cache_db/",
    "/mesa_shader_cache_sf/",
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
    ".wasm", ".xpi", ".ui", ".css", ".rcc", ".spv",
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

STEAM_UI_CACHE_FILE_MAX = 512 * MIB
FIREFOX_WEB_CACHE_FILE_MAX = 512 * MIB
HYTALE_WORLD_FILE_MAX = 1 * GIB
VRCHAT_CONTENT_CACHE_FILE_MAX = 512 * MIB

RECENCY_FIRST_BUDGET_KEYS = {
    "steam_htmlcache",
    "firefox_webcache",
    "chromium_webcache",
    "electron_webcache",
    "desktop_shader_cache",
    "desktop_compiled_cache",
    "app_catalog",
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
        return lower

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
            # Keep the existing recent-unit budget, after daily desktop/web
            # use. Downloaded worlds/avatars remain useful late cache filler.
            return (6, 10000, 0)
        return (99, 0, 0)

    if (
        is_vip_full_app_path(path)
        or is_vip_steam_client_path(path)
        or is_vip_vrchat_runtime_path(path)
    ):
        if size > 16 * MIB and (
            name.endswith(MEDIA_SUFFIXES)
            or (name not in ELECTRON_RUNTIME_NAMES and name.endswith(
                GAME_ASSET_SUFFIXES + (".assets", ".ress", ".resource", ".vrca", ".vrcw", ".unity3d")
            ))
        ):
            return (6, 200, 0)
        # Retain every VIP target, while letting core OS/toolkit files (tier 0)
        # precede application payloads even on small-memory machines.
        return (1, 10000, 0)

    return None


def is_steam_ui_cache_path(path: str) -> bool:
    return path_contains_any(path, STEAM_UI_CACHE_SUBSTRINGS)


def is_firefox_web_cache_path(path: str) -> bool:
    return (
        (path_contains_any(path, FIREFOX_WEB_CACHE_SUBSTRINGS)
         or FIREFOX_USER_PATH_RE.search(path) is not None)
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
    path = path.lower()
    if "/vrchat/vrchat/" not in path:
        return False
    return any("/" + name + "/" in path.rstrip("/") + "/" for name in (
        "cache-windowsplayer", "texturediskcache-windowsplayer",
        "httpcache-windowsplayer", "avatars", "avatarparts", "worlds",
    ))


def is_selective_steam_runtime_path(path: str) -> bool:
    return path_contains_any(path, SELECTIVE_STEAM_RUNTIME_SUBSTRINGS)


# Match application namespaces, not arbitrary folders named Cache. Matching
# both native and sandbox XDG layouts keeps the policy independent of distro,
# architecture, browser release channel, and Flatpak/Snap packaging.
FIREFOX_USER_PATH_RE = re.compile(
    r"/(?:\.mozilla/firefox|"
    r"(?:\.config|\.cache|config|cache)/(?:mozilla/firefox|firefox|librewolf|floorp|zen|waterfox)|"
    r"\.(?:librewolf|floorp|zen|waterfox))(?=/|$)"
)
CHROMIUM_USER_PATH_RE = re.compile(
    r"/(?:\.config|\.cache|config|cache)/(?:"
    r"google-chrome(?:-[a-z]+)?|chromium(?:-browser)?|"
    r"bravesoftware/brave-browser(?:-[a-z]+)?|microsoft-edge(?:-[a-z]+)?|"
    r"vivaldi(?:-snapshot)?|opera(?:-(?:beta|developer))?|thorium|helium)(?=/|$)"
)
ELECTRON_USER_PATH_RE = re.compile(
    r"/(?:\.config|\.cache|config|cache)/(?:"
    r"discord(?:canary|ptb|development)?|vesktop|slack|signal|element|"
    r"teams-for-linux|code(?:-insiders)?|vscodium)(?=/|$)|"
    r"/(?:\.config|config)/obs-studio/plugin_config/obs-browser(?=/|$)"
)
WEB_CACHE_FILE_MAX = 512 * MIB


def browser_cache_kind(path: str) -> Optional[tuple[str, str]]:
    """Return a bounded cache family and resource kind, including cache roots."""
    # Most inventory files are system/app code, not browser caches.
    if not any(token in path for token in ("cache", "storage", "shared dictionary", "shared_dictionary")):
        return None

    p = path.rstrip(os.sep) + os.sep
    if is_steam_ui_cache_path(p):
        family, tail = "steam_htmlcache", p
    else:
        match = FIREFOX_USER_PATH_RE.search(p)
        if match is not None:
            family = "firefox_webcache"
        else:
            match = CHROMIUM_USER_PATH_RE.search(p)
            if match is not None:
                family = "chromium_webcache"
            else:
                match = ELECTRON_USER_PATH_RE.search(p)
                if match is None:
                    return None
                family = "electron_webcache"
        # Ignore the sandbox's XDG 'cache' directory itself: only match cache
        # structures below the application namespace.
        tail = p[match.end():]

    if family == "firefox_webcache":
        if "/startupcache/" in tail:
            return family, "code"
        if "/cache2/index" in tail:
            return family, "index"
        if "/cache2/entries/" in tail or "/offlinecache/" in tail:
            return family, "http"
        if "/storage/default/" in tail or "/storage/permanent/" in tail:
            if "/cache/" in tail:
                return family, "http"
            # Prioritize site databases, not arbitrary large IndexedDB blobs.
            name = os.path.basename(path)
            if "/idb/" in tail and name.endswith((".sqlite", ".sqlite-wal", ".sqlite-shm")):
                return family, "state"
        return None

    if "/code cache/" in tail or "/service worker/scriptcache/" in tail:
        return family, "code"
    if "/service worker/database/" in tail:
        return family, "state"
    if "/service worker/cachestorage/" in tail:
        return family, "http"
    if "/shared dictionary/" in tail or "/shared_dictionary/" in tail:
        return family, "code"
    if "/local storage/leveldb/" in tail or "/session storage/" in tail:
        return family, "state"
    if "/indexeddb/" in tail:
        name = os.path.basename(path)
        if name.endswith((".ldb", ".log", ".sqlite", ".sqlite-wal", ".sqlite-shm")) or name == "current" or name.startswith("manifest-"):
            return family, "state"
    if any(token in tail for token in ("/gpucache/", "/grshadercache/", "/dawncache/", "/dawngraphitecache/", "/dawnwebgpucache/")):
        return family, "shader"
    if "/cache/" in tail:
        return family, "http"
    return None


def classify_web_cache(path: str, name: str, size: int) -> Optional[tuple[int, int, int]]:
    kind = browser_cache_kind(path)
    if kind is None:
        return None
    if size > WEB_CACHE_FILE_MAX:
        # Remain eligible as late filler, within the family's byte budget.
        return (5, 100, 0)
    confidence = {"index": 1000, "code": 940, "state": 840, "http": 760, "shader": 740}[kind[1]]
    if name in {"index", "the-real-index", "current"} or name.startswith("manifest-"):
        confidence += 140
    return (3, confidence, 0)


GLOBAL_SHADER_CACHE_RE = re.compile(
    r"/(?:\.cache|cache)/(?:mesa_shader_cache(?:_db|_sf)?|nvidia)(?=/|$)|"
    r"/\.nv/glcache(?=/|$)"
)
USER_CACHE_PATH_RE = re.compile(r"/\.cache/|/\.var/app/[^/]+/cache/")


def is_global_shader_cache_path(path: str) -> bool:
    return GLOBAL_SHADER_CACHE_RE.search(path) is not None


def is_desktop_compiled_cache_path(path: str) -> bool:
    return (
        "/qmlcache/" in path
        and name_is_qml_cache(os.path.basename(path))
        and USER_CACHE_PATH_RE.search(path) is not None
    )


def name_is_qml_cache(name: str) -> bool:
    return name.endswith((".qmlc", ".jsc", ".mjsc"))


def is_targeted_browser_like_cache_path(path: str) -> bool:
    return (
        is_steam_ui_cache_path(path)
        or is_firefox_web_cache_path(path)
        or is_vrchat_content_cache_path(path)
        or browser_cache_kind(path) is not None
    )


def file_is_executable(rec: FileRec) -> bool:
    return bool(rec.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def is_shared_library_name(name: str) -> bool:
    return name.endswith(".so") or ".so." in name


def is_browser_profile_path(path: str) -> bool:
    return (
        path_contains_any(path, BROWSER_PROFILE_SUBSTRINGS)
        or FIREFOX_USER_PATH_RE.search(path) is not None
        or CHROMIUM_USER_PATH_RE.search(path) is not None
    )


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


# Resource namespaces identify the installed desktop/toolkit itself. No distro
# default is assumed: the same component paths work on Debian/Ubuntu/Pop/Mint,
# Fedora's lib64 layout, and Arch/CachyOS, including user-installed resources.
DESKTOP_COMPONENT_PREFIXES = (
    "/usr/share/cosmic", "/usr/share/gnome-shell", "/usr/share/cinnamon",
    "/usr/share/nemo", "/usr/share/mate", "/usr/share/caja",
    "/usr/share/xfce4", "/usr/share/xfwm4", "/usr/share/thunar",
    "/usr/share/plasma", "/usr/share/kwin", "/usr/share/kf6",
    "/usr/share/kservices6", "/usr/share/kservicetypes6", "/usr/share/kxmlgui6",
    "/usr/share/hypr", "/usr/share/niri", "/usr/share/waybar",
    "/usr/share/pipewire", "/usr/share/wireplumber",
)
DESKTOP_USER_CONFIG_RE = re.compile(
    r"/(?:\.config|config)/(?:cosmic|com\.system76\.cosmic[^/]*|"
    r"gnome-shell|cinnamon|nemo|mate|caja|xfce4|thunar|"
    r"gtk-3\.0|gtk-4\.0|dconf|fontconfig|autostart|menus|"
    r"hypr|sway|niri|waybar|rofi|fuzzel|mako|dunst|wlogout|"
    r"pipewire|wireplumber|pulse)(?=/|$)"
)
DESKTOP_USER_PLUGIN_RE = re.compile(
    r"/(?:\.local/share|data)/(?:gnome-shell/extensions|"
    r"cinnamon/(?:applets|desklets|extensions)|plasma/(?:plasmoids|desktoptheme|look-and-feel)|"
    r"kwin/(?:scripts|effects|tabbox)|pop-launcher/(?:plugins|scripts)|"
    r"nemo/(?:actions|scripts)|nautilus/scripts|themes)(?=/|$)"
)
DESKTOP_USER_SUPPORT_RE = re.compile(
    r"/(?:\.local/share|data)/(?:applications|icons|fonts|mime|gvfs-metadata)(?=/|$)|"
    r"/\.(?:themes|icons|fonts)(?=/|$)"
)
KDE_USER_CONFIG_NAMES = {
    "kdeglobals", "kwinrc", "plasmashellrc", "kglobalshortcutsrc",
    "kscreenlockerrc", "kiorc", "dolphinrc", "konsolerc", "katerc",
    "plasma-org.kde.plasma.desktop-appletsrc", "breezerc", "kcminputrc",
}
DAILY_UI_SUFFIXES = (".ui", ".css", ".rcc", ".ron", ".spv")
APP_CATALOG_PREFIXES = (
    "/var/cache/swcatalog", "/var/lib/swcatalog", "/usr/share/swcatalog",
    "/var/cache/app-info", "/var/lib/app-info", "/usr/share/app-info",
)


def is_app_catalog_path(path: str, name: str) -> bool:
    return (
        path_has_prefix(path, APP_CATALOG_PREFIXES)
        and name.endswith((".xml", ".yml", ".yaml", ".xml.gz", ".yml.gz", ".yaml.gz", ".xb", ".cache", ".jxl"))
    )


def classify_daily_resource(rec: FileRec, path: str, name: str) -> Optional[tuple[int, int, int]]:
    size = rec.size
    system_runtime = path_has_prefix(path, HOT_SYSTEM_PREFIXES)

    # Tiny runtime indexes are read alongside libraries, but their filenames
    # do not look like executable code. Match runtime formats, not GIR sources.
    if system_runtime and (
        (name.endswith(".typelib") and size <= 32 * MIB)
        or (name in {"giomodule.cache", "loaders.cache", "immodules.cache", "qmldir"} and size <= 4 * MIB)
    ):
        return (0, 1400, 0)
    if size <= MIB and path.startswith("/usr/share/glvnd/egl_vendor.d/") and name.endswith(".json"):
        return (0, 1400, 0)

    cache_match = USER_CACHE_PATH_RE.search(path)
    if size <= 32 * MIB and (
        path.startswith("/var/cache/fontconfig/")
        or (cache_match is not None and path[cache_match.end():].startswith("fontconfig/"))
    ) and (".cache-" in name or name.endswith(".cache")):
        return (0, 1380, 0)
    if cache_match is not None:
        tail = path[cache_match.end():]
        if size <= 32 * MIB and tail.startswith("gstreamer-1.0/") and name.startswith("registry") and name.endswith(".bin"):
            return (0, 1380, 0)
        if size <= 64 * MIB and (name.startswith(("ksycoca5_", "ksycoca6_")) or name == "icon-cache.kcache"):
            return (0, 1360, 0)
        if is_desktop_compiled_cache_path(path) and size <= 64 * MIB:
            return (2, 1120, 0)

    if is_global_shader_cache_path(path) and size <= 256 * MIB:
        # Preserve existing shader-file priority; also recognize hashed binary
        # entries and Mesa's database/single-file layouts.
        return (1 if name.endswith(SHADER_SUFFIXES) else 2, 760, 0)

    if size <= 128 * MIB:
        firefox = FIREFOX_USER_PATH_RE.search(path) is not None
        chromium = CHROMIUM_USER_PATH_RE.search(path) is not None
        if firefox and "/extensions/" in path and name.endswith(".xpi"):
            return (1, 10600, 0)
        if chromium and "/extensions/" in path and (
            name.endswith(RUNTIME_SUFFIXES + (".json", ".html", ".css"))
        ):
            return (1, 10600, 0)
        if (firefox or chromium) and name in BROWSER_STARTUP_NAMES:
            return (2, 1080, 0)

    if size <= 16 * MIB:
        # Standard share/lib locations vary between distro families. Keep
        # support data bounded so opaque, large payloads do not jump the queue.
        share_path = path.replace("/usr/local/share/", "/usr/share/", 1) if path.startswith("/usr/local/share/") else path
        component = path_has_prefix(share_path, DESKTOP_COMPONENT_PREFIXES)
        user_plugin = DESKTOP_USER_PLUGIN_RE.search(path) is not None
        launcher_plugin = "/pop-launcher/plugins/" in path and system_runtime
        if component or user_plugin or launcher_plugin:
            if file_is_executable(rec) or is_shared_library_name(name) or name.endswith(RUNTIME_SUFFIXES + DAILY_UI_SUFFIXES + (".gresource", ".typelib")) or name == "qmldir":
                return (1, 10400, 0)
            if size <= 4 * MIB and not name.endswith(MEDIA_SUFFIXES + ARCHIVE_SUFFIXES + DOCUMENT_SUFFIXES + GAME_ASSET_SUFFIXES):
                return (2, 1020, 0)

        config = DESKTOP_USER_CONFIG_RE.search(path) is not None
        kde_config = name in KDE_USER_CONFIG_NAMES and ("/.config/" in path or "/config/" in path)
        if (config or kde_config) and size <= 4 * MIB and not name.endswith(MEDIA_SUFFIXES + ARCHIVE_SUFFIXES + DOCUMENT_SUFFIXES + GAME_ASSET_SUFFIXES):
            return (2, 1040, 0)

        if path_has_prefix(share_path, DESKTOP_SUPPORT_PREFIXES) or DESKTOP_USER_SUPPORT_RE.search(path) is not None:
            if not name.endswith(MEDIA_SUFFIXES + ARCHIVE_SUFFIXES + DOCUMENT_SUFFIXES + GAME_ASSET_SUFFIXES):
                return (2, 1000, 0)

        if (path.startswith(("/usr/share/", "/usr/local/share/")) or system_runtime) and name.endswith(DAILY_UI_SUFFIXES + (".gresource",)):
            return (2, 920, 0)

    # Software-center catalogs and installed-package records help occasional
    # desktop actions, after interactive code/resources and browser data.
    if size <= 64 * MIB:
        if is_app_catalog_path(path, name):
            return (4, 820, 0)
        if path == "/var/lib/dpkg/status" or path.startswith("/var/lib/pacman/local/") and name in {"desc", "files"}:
            return (4, 800, 0)
        if path.startswith(("/usr/lib/sysimage/rpm/", "/var/lib/rpm/")) and name in {"rpmdb.sqlite", "rpmdb.sqlite-wal", "rpmdb.sqlite-shm", "packages.db", "packages"}:
            return (4, 800, 0)
    return None


def should_prune_dir(path: str) -> bool:
    p = os.path.normpath(path).lower()

    # Repositories contain installation/download artifacts, not the deployed
    # files that applications actually map. Prune these even inside VIP trees.
    if any(marker in p + "/" for marker in (
            "/.local/share/flatpak/repo/", "/.local/share/containers/storage/",
            "/.cache/pip/", "/.cache/uv/", "/.npm/_cacache/", "/.cargo/registry/cache/")):
        return True

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

    if path_contains_any(p + "/", PRUNE_DIR_SUBSTRINGS):
        return True

    # Do not scan arbitrary project dependency forests, but keep packaged
    # Electron app runtime node_modules because those can be part of app launch.
    if "/node_modules/" in p + "/" and "/resources/app/node_modules/" not in p + "/":
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

    if not path_has_prefix(path, HARD_COLD_PREFIXES):
        web_cache = classify_web_cache(path, name, size)
        if web_cache is not None:
            return web_cache

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

            return (6, confidence, 0)

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
            return (6, 840, 0)
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

    daily_resource = classify_daily_resource(rec, path, name)
    if daily_resource is not None:
        return daily_resource

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
    defaults = {
        "steam_htmlcache": "1G", "firefox_webcache": "4G", "chromium_webcache": "4G",
        "electron_webcache": "2G", "desktop_shader_cache": "1G", "desktop_compiled_cache": "256M",
        "app_catalog": "256M", "hytale_world": "2G", "vrchat_content_cache": "2G",
    }
    return {key: max(0, parse_size(cfg.get(key + "_budget_bytes", default)) or 0)
            for key, default in defaults.items()}


def cache_budget_file_caps(cfg: dict) -> dict[str, int]:
    defaults = {"steam_htmlcache": 65536, "firefox_webcache": 131072,
                "chromium_webcache": 131072, "electron_webcache": 65536,
                "desktop_shader_cache": 32768, "desktop_compiled_cache": 32768, "app_catalog": 16384}
    return {key: max(0, int(cfg.get(key + "_max_files", default))) for key, default in defaults.items()}


def cache_budget_key(rec: FileRec) -> Optional[str]:
    if rec.budget:
        return rec.budget
    path = os.path.normpath(rec.path).lower()

    web_cache = browser_cache_kind(path)
    if web_cache is not None:
        return web_cache[0]

    if is_global_shader_cache_path(path):
        return "desktop_shader_cache"
    if is_desktop_compiled_cache_path(path):
        return "desktop_compiled_cache"
    if is_app_catalog_path(path, os.path.basename(path)):
        return "app_catalog"

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
        browser_cache_kind(lower) is not None
        or is_global_shader_cache_path(lower)
        or is_desktop_compiled_cache_path(lower)
        or is_app_catalog_path(lower, os.path.basename(lower))
        or is_firefox_web_cache_path(lower)
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
        for path in cfg.get("_resolved_roots", cfg.get("include_paths", ["/"]))
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
    return max(1, min(wanted, max_workers, int(cfg.get("metadata_worker_cap", 12))))


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
        dev=st.st_dev, ino=st.st_ino,
        mtime_ns=st.st_mtime_ns, ctime_ns=st.st_ctime_ns,
    )

    # Do not spend inventory RAM on files the policy can never select.
    if classify_file(rec)[0] >= 99:
        return None

    return rec


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
    if rec.priority:
        return rec.priority
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


def bytes_to_gib(n: int) -> float:
    return round(n / GIB, 2)


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
        self.last_error = ""
        self.stderr_thread = None
        self.excludes = []
        self.nul_format = False

    def _write_watch_list(self, cfg: dict) -> None:
        WATCH_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        lines = []

        for p in normalized_roots(cfg):
            lines.append(os.path.normpath(p))

        excluded = {
            os.path.normpath(p)
            for p in cfg["exclude_prefixes"]
        }
        excluded.update(os.path.normpath(p) for p in HARD_COLD_PREFIXES)
        excluded.update((str(STATE_PATH), str(RUNTIME_PATH)))

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
        if path_is_under(path, str(STATE_PATH)) or path_is_under(path, str(RUNTIME_PATH)):
            return False
        excludes = self.excludes

        if path_is_excluded(path, excludes):
            return False

        if should_prune_dir(path):
            return False

        return any(path_is_under(path, root) for root in self.include_paths)

    def _start_process(self, cmd: list[str], mode: str) -> bool:
        try:
            help_text = subprocess.run([cmd[0], "--help"], stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, timeout=3).stdout
            self.nul_format = b"--no-newline" in help_text
        except (OSError, subprocess.TimeoutExpired):
            self.nul_format = False
        if self.nul_format:
            index = cmd.index("--format") + 1
            cmd[index] += "%0"
            cmd.append("--no-newline")
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0,
        )
        self.mode = mode
        proc = self.proc
        def drain_errors():
            try:
                for line in proc.stderr:
                    self.last_error = line.decode("utf-8", "backslashreplace").strip()[:1024]
                if proc.poll() not in (None, 0) and not self.stop_event.is_set():
                    logging.warning("%s watcher exited: %s", mode, self.last_error or str(proc.returncode))
            except (OSError, ValueError):
                pass
        self.stderr_thread = threading.Thread(target=drain_errors, daemon=True, name="watcher-errors")
        self.stderr_thread.start()

        # fanotify setup is essentially immediate. If this binary/kernel
        # combination rejects the request, fall back to recursive inotify.
        time.sleep(0.05)
        return self.proc.poll() is None

    def event_lines(self):
        proc = self.proc
        separator = b"\0" if self.nul_format else b"\n"
        pending = b""
        while not self.stop_event.is_set():
            data = os.read(proc.stdout.fileno(), 65536)
            if not data:
                return
            pending += data
            while separator in pending:
                line, pending = pending.split(separator, 1)
                yield os.fsdecode(line)
            if len(pending) > 65536:
                pending = b""
                self.resync_event.set()

    def start(self, cfg: dict) -> None:
        if (
            self.mode == "fanotify-filesystem"
            and self.proc is not None
            and self.proc.poll() is not None
        ):
            self.fanotify_disabled = True

        self.stop()
        self.cfg = dict(cfg)
        self.include_paths = normalized_roots(cfg)
        self.excludes = [os.path.normpath(p) for p in cfg.get("exclude_prefixes", [])]
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
                "--exclude",
                r"(^|/)(\.git|\.svn|\.hg)(/|$)|/\.local/share/(flatpak/repo|containers/storage)(/|$)|/\.cache/(pip|uv)(/|$)|/\.npm/_cacache(/|$)",
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
                for line in self.event_lines():
                    if self.stop_event.is_set():
                        break

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
                if not self.stop_event.is_set():
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



# Persistent state contains filenames and usage counts, never file contents.
def atomic_json(path: Path, value, *, mode: int = 0o600, durable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, separators=(",", ":"), ensure_ascii=True)
            output.write("\n")
            if durable:
                output.flush()
                os.fsync(output.fileno())
        os.replace(temp, path)
        if durable:
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def read_json(path: Path, default=None):
    try:
        with path.open(encoding="utf-8") as source:
            return json.load(source)
    except (OSError, ValueError):
        return default


def page_bytes(size: int) -> int:
    return ((size + PAGE_SIZE - 1) // PAGE_SIZE) * PAGE_SIZE


def stop_proc(proc) -> None:
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    finally:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def record_key(rec: FileRec) -> tuple:
    # Aliases/hard links share page cache. Change detection additionally uses
    # ctime: replacing a file with one of the same size/mtime is still detected.
    return (rec.dev, rec.ino, rec.size, rec.mtime_ns, rec.ctime_ns)


def record_to_list(rec: FileRec) -> list:
    return [rec.path, rec.size, rec.mtime, rec.mode, rec.dev, rec.ino,
            rec.mtime_ns, rec.ctime_ns, list(rec.priority), rec.budget]


def record_from_list(values: list) -> FileRec:
    if not isinstance(values, list) or len(values) != 10:
        raise ValueError("invalid saved file record")
    path, size, stamp, mode, dev, ino, mtime_ns, ctime_ns, priority, budget = values
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path:
        raise ValueError("invalid saved path")
    if (not isinstance(size, int) or size <= 0 or not isinstance(priority, list)
            or len(priority) != 5 or any(not isinstance(x, (int, float)) or not math.isfinite(x) for x in priority)):
        raise ValueError("invalid saved size/priority")
    return FileRec(path, size, float(stamp), int(mode), int(dev), int(ino),
                   int(mtime_ns), int(ctime_ns), tuple(priority), str(budget))


def stat_record(path: str, st=None) -> Optional[FileRec]:
    try:
        st = st or os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size <= 0:
            return None
        # Keep regex/classification work out of the I/O threads. Observation
        # frequency is learned independently; this timestamp is only a tie-break.
        return FileRec(path, st.st_size, max(st.st_mtime, st.st_atime),
                       st.st_mode, st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns)
    except (OSError, ValueError):
        return None


def normalized_roots(cfg: dict) -> list[str]:
    roots = []
    # Resolve only explicitly discovered installation roots. Directory walks
    # never follow arbitrary symlinks in Wine prefixes or user data.
    for path in build_include_paths(cfg):
        path = os.path.realpath(path)
        if path_is_excluded(path, cfg.get("exclude_prefixes", [])):
            continue
        if os.path.isdir(path):
            roots.append((path, safe_dev(path)))
    result = []
    for path, device in sorted(set(roots), key=lambda item: (len(item[0]), item[0])):
        if device is None:
            continue
        if not root_allows_cross_filesystem(path, cfg) and any(device == dev and path_is_under(path, parent) for parent, dev in result):
            continue
        result.append((path, device))
    cfg["_root_devices"] = dict(result)
    return [path for path, _ in result]


def record_device_allowed(rec: FileRec, cfg: dict, roots: list[str]) -> bool:
    if not cfg.get("stay_on_filesystem", True):
        return True
    root = governing_include_root(rec.path, roots)
    if root is None:
        return False
    if root_allows_cross_filesystem(root, cfg):
        return True
    devices = cfg.setdefault("_root_devices", {})
    if root not in devices:
        devices[root] = safe_dev(root)
    return rec.dev == devices[root]


def cache_path_allowed(path: str, cfg: dict, roots: list[str]) -> bool:
    if not path.startswith("/") or "\0" in path:
        return False
    if path_is_under(path, str(STATE_PATH)) or path_is_under(path, str(RUNTIME_PATH)):
        return False
    if path_has_prefix(path, ("/proc", "/sys", "/dev", "/run")):
        return False
    return (not path_is_excluded(path, cfg.get("exclude_prefixes", []))
            and not path_has_prefix(path.lower(), HARD_COLD_PREFIXES)
            and any(path_is_under(path, root) for root in roots))


def memory_watermarks(meminfo: dict, cfg: dict) -> tuple[int, int, int]:
    total = meminfo["MemTotal"]
    floor = parse_size(cfg.get("target_available_bytes", "2G")) or 2 * GIB
    reserve = parse_size(cfg.get("target_grow_to_available_bytes", "3G")) or 3 * GIB
    above = parse_size(cfg.get("target_grow_above_available_bytes", "4G")) or 4 * GIB
    if cfg.get("adaptive_memory_reserve", True):
        # These are reserves, not permanent allocations. Small machines must
        # not inherit the old fixed 6 GiB reserve; larger machines need room for
        # simultaneous browser/game allocation bursts.
        scaled = min(12 * GIB, max(1536 * MIB, int(total * 0.075)))
        if cfg.get("memory_profile") == "low_ram":
            reserve = max(int(total * 0.12), 1536 * MIB)
            floor = max(int(total * 0.075), 768 * MIB)
            above = reserve + 512 * MIB
            overrides = cfg.get("low_ram_profile_overrides", {})
            if "target_available_bytes" in overrides:
                floor = parse_size(overrides["target_available_bytes"]) or floor
            if "target_grow_to_available_bytes" in overrides:
                reserve = parse_size(overrides["target_grow_to_available_bytes"]) or reserve
            if "target_grow_above_available_bytes" in overrides:
                above = parse_size(overrides["target_grow_above_available_bytes"]) or above
        else:
            reserve = max(reserve, scaled)
            above = max(above, reserve + 512 * MIB)
        if meminfo.get("SwapTotal", 0) == 0:
            reserve = max(reserve, min(12 * GIB, int(total * 0.10)))
    # A malformed old config cannot reserve more memory than the machine has.
    floor = min(floor, max(256 * MIB, int(total * 0.25)))
    reserve = min(max(floor, reserve), max(floor, int(total * 0.4)))
    return floor, reserve, max(reserve + 128 * MIB, min(above, int(total * 0.5)))


class PressurePolicy:
    """Cheap supervisor-only pressure policy; discovery cannot block release."""
    def __init__(self):
        self.samples = deque(maxlen=120)
        self.psi = parse_memory_psi_totals()
        self.pause_until = 0.0
        self.last_release = 0.0
        self.reason = "starting"

    def evaluate(self, meminfo: dict, cfg: dict, owned_locked: int,
                 own_anon: int = 0, now: Optional[float] = None) -> tuple[int, bool]:
        now = time.monotonic() if now is None else now
        floor, reserve, above = memory_watermarks(meminfo, cfg)
        available = meminfo["MemAvailable"]
        external = max(0, meminfo["MemTotal"] - available - owned_locked - own_anon)
        self.samples.append((now, external))
        while self.samples and self.samples[0][0] < now - 10:
            self.samples.popleft()
        oldest, baseline = self.samples[0]
        growth = max(0, external - baseline)
        rate = growth / max(1.0, now - oldest)
        prediction = min(4 * GIB, int(rate * float(cfg.get("rapid_memory_prediction_seconds", 3))))
        psi = parse_memory_psi_totals()
        delta = tuple(max(0, a - b) for a, b in zip(psi, self.psi))
        self.psi = psi
        stalled = (delta[0] >= int(cfg.get("psi_memory_some_stall_threshold_us", 100000))
                   or delta[1] >= int(cfg.get("psi_memory_full_stall_threshold_us", 20000)))
        release = 0
        self.reason = "available"
        if available < floor:
            release = reserve - available
            self.reason = "available memory below reserve"
        elif growth >= 256 * MIB and available - prediction < reserve:
            release = reserve + prediction - available
            self.reason = "projected application memory demand"
        elif stalled:
            # PSI may reflect local/cgroup pressure even with global headroom.
            # Make one modest release, then sample again rather than discarding
            # multiple GiB every 250 ms for the same allocation burst.
            if now - self.last_release >= 2:
                release = min(owned_locked, 512 * MIB)
            self.reason = "kernel memory pressure"
        pause = bool(release or stalled or available < reserve)
        if release or stalled:
            self.pause_until = max(self.pause_until, now + float(
                cfg.get("memory_pressure_regrow_cooldown_seconds", 10)))
        if release:
            self.last_release = now
        return min(owned_locked, max(0, release)), pause or now < self.pause_until


class IOActivity:
    """Back off for other work on a busy disk, not for our own prefetch I/O."""
    def __init__(self):
        self.previous = None

    @staticmethod
    def snapshot():
        root = Path("/sys/fs/cgroup")
        group = root
        with open("/proc/self/cgroup", encoding="utf-8") as source:
            for line in source:
                if line.startswith("0::"):
                    candidate = root / line.strip().split("::", 1)[1].lstrip("/")
                    if candidate.is_dir():
                        group = candidate
                    break
        own = {}
        with (group / "io.stat").open() as source:
            for line in source:
                parts = line.split()
                values = dict(part.split("=", 1) for part in parts[1:] if "=" in part)
                own[parts[0]] = int(values.get("rbytes", 0)) + int(values.get("wbytes", 0))
        disks = {}
        with open("/proc/diskstats", encoding="ascii") as source:
            for line in source:
                fields = line.split()
                if len(fields) < 14:
                    continue
                key = fields[0] + ":" + fields[1]
                # Match the exact block device used by cgroup accounting;
                # adding disks plus partitions would double-count our traffic.
                if key in own:
                    disks[key] = ((int(fields[5]) + int(fields[9])) * 512, int(fields[12]))
        return disks, own

    def busy(self, now=None):
        now = time.monotonic() if now is None else now
        try:
            disks, own = self.snapshot()
        except (OSError, ValueError, IndexError):
            return False
        previous = self.previous
        self.previous = (now, disks, own)
        if previous is None:
            return False
        then, old_disks, old_own = previous
        seconds = max(0.1, now - then)
        for key in disks.keys() & old_disks.keys() & old_own.keys():
            traffic = max(0, disks[key][0] - old_disks[key][0])
            our_traffic = max(0, own[key] - old_own[key])
            external = max(0, traffic - our_traffic)
            utilization = max(0, disks[key][1] - old_disks[key][1]) / (1000 * seconds)
            if external / seconds >= 4 * MIB and utilization >= 0.8:
                return True
        return False


def process_memory(pid: int) -> tuple[int, int]:
    locked = anon = 0
    resident_file = None
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as source:
            for line in source:
                if line.startswith("VmLck:"):
                    locked = int(line.split()[1]) * KIB
                elif line.startswith("RssAnon:"):
                    anon = int(line.split()[1]) * KIB
                elif line.startswith("RssFile:"):
                    resident_file = int(line.split()[1]) * KIB
    except (OSError, ValueError):
        pass
    # VmLck can account an mlock range before all its I/O completes. Bound the
    # estimate by resident file pages so our own loading does not masquerade as
    # sudden external memory growth. The final worker acknowledgement confirms
    # that the requested mappings have finished faulting and locking.
    return min(locked, resident_file) if resident_file is not None else locked, anon


@dataclass
class CacheWorker:
    proc: subprocess.Popen
    records: list[FileRec]
    requested: int
    started: float
    priority: tuple
    stop_event: threading.Event = field(default_factory=threading.Event)
    ready: threading.Event = field(default_factory=threading.Event)
    failed: threading.Event = field(default_factory=threading.Event)
    locked: int = 0
    last_progress: float = field(default_factory=time.monotonic)
    reported_pages: int = 0
    warnings: int = 0
    diagnostic: str = ""
    reader: Optional[threading.Thread] = None
    feeder: Optional[threading.Thread] = None
    stopped: bool = False
    acknowledged_at: float = 0.0
    last_sample: float = 0.0


def start_cache_worker(records: list[FileRec], cfg: dict) -> CacheWorker:
    # A PTY makes vmtouch's final LOCKED acknowledgement line-buffered even on
    # older builds. Drain it continuously; never leave stderr in an unread pipe.
    master, slave = os.openpty()
    maximum = max(rec.size for rec in records)
    binary = cfg.get("vmtouch_binary") or shutil.which("vmtouch") or str(Path(__file__).with_name("vmtouch"))
    try:
        proc = subprocess.Popen(
            [binary, "-l", "-0", "-b", "-", "-m", str(maximum)],
            stdin=subprocess.PIPE, stdout=slave, stderr=slave, close_fds=True,
        )
    except BaseException:
        os.close(master)
        raise
    finally:
        os.close(slave)
    worker = CacheWorker(proc, records, sum(page_bytes(r.size) for r in records),
                         time.monotonic(), records[0].priority or (99,))

    def feed():
        try:
            assert proc.stdin is not None
            for rec in records:
                if worker.stop_event.is_set():
                    break
                # EVERY path is terminated, including a one-file chunk.
                proc.stdin.write(os.fsencode(rec.path) + b"\0")
            proc.stdin.close()
        except (OSError, ValueError):
            if not worker.stop_event.is_set():
                worker.failed.set()
        finally:
            if proc.stdin is not None:
                try:
                    proc.stdin.close()
                except OSError:
                    pass

    def drain():
        pending = b""
        try:
            while not worker.stop_event.is_set():
                if not select.select([master], [], [], 0.5)[0]:
                    if proc.poll() is not None:
                        break
                    continue
                data = os.read(master, 8192)
                if not data:
                    break
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    match = re.match(rb"LOCKED (\d+) pages", line)
                    if match:
                        worker.reported_pages = int(match.group(1))
                        worker.ready.set()
                    elif b"WARNING:" in line or b"FATAL:" in line or b"ERROR:" in line:
                        worker.warnings += 1
                        worker.diagnostic = line.decode("utf-8", "backslashreplace")[:1024]
                # A pathological filename must not grow the output buffer.
                pending = pending[-16384:]
        except OSError as error:
            if error.errno != errno.EIO and not worker.stop_event.is_set():
                worker.failed.set()
        finally:
            os.close(master)

    worker.reader = threading.Thread(target=drain, daemon=True, name="cache-ack")
    worker.feeder = threading.Thread(target=feed, daemon=True, name="cache-feed")
    worker.reader.start()
    worker.feeder.start()
    return worker


def signal_worker(worker: CacheWorker) -> None:
    worker.stop_event.set()
    worker.stopped = True
    try:
        worker.proc.terminate()
    except ProcessLookupError:
        pass


def reap_workers(retired: list[tuple[float, CacheWorker]]) -> None:
    now = time.monotonic()
    for started, worker in list(retired):
        if worker.proc.poll() is not None:
            retired.remove((started, worker))
        elif now - started > 2:
            try:
                worker.proc.kill()
            except ProcessLookupError:
                pass


def worker_chunks(records: list[FileRec], cfg: dict):
    stable_limit = min(parse_size(cfg.get("vmtouch_chunk_target_bytes", "128M")) or 128 * MIB,
                       256 * MIB)
    mutable_limit = min(stable_limit, 64 * MIB)
    max_paths = min(8192, int(cfg.get("vmtouch_chunk_max_paths", 8192)))
    current, size, previous_mutable = [], 0, None
    for rec in records:
        mutable = bool(rec.budget) or any(marker in rec.path.lower() for marker in (
            "/.config/", "/.cache/", "/.mozilla/", "/.var/app/", "/config/", "/pfx/"))
        limit = mutable_limit if mutable else stable_limit
        cost = page_bytes(rec.size)
        if current and (mutable != previous_mutable or size + cost > limit or len(current) >= max_paths):
            yield current
            current, size = [], 0
        current.append(rec)
        size += cost
        previous_mutable = mutable
    if current:
        yield current

DB_SCHEMA = 1


def classify_batch(items):
    """CPU-only batch. Spawn workers never receive the inventory or database."""
    rows = []
    for rec, hits, last_use in items:
        priority = selection_sort_key(rec)
        if priority is None:
            rows.append((rec, None, "", ""))
            continue
        budget = cache_budget_key(rec) or ""
        unit = dynamic_cache_root_key(rec) or ""
        key = list(priority[:5])
        # Learn portable/custom applications too, without turning a frequent
        # media read or a whole game asset pack into startup code. Extension
        # checks matter on filesystems that report every file as executable.
        name = os.path.basename(rec.path).lower()
        observed_code = (rec.size <= 512 * MIB and not budget
                         and (file_is_executable(rec) or is_shared_library_name(name)
                              or name.endswith((".dll", ".exe")))
                         and not name.endswith(MEDIA_SUFFIXES + ARCHIVE_SUFFIXES
                                               + DOCUMENT_SUFFIXES + GAME_ASSET_SUFFIXES + PACKAGE_IMAGE_SUFFIXES))
        if hits > 0 and observed_code and key[0] >= 5:
            age_days = max(0.0, (time.time() - last_use) / 86400)
            if min(32.0, hits) * (0.5 ** (age_days / 14.0)) >= 0.5:
                key[0] = 1
        if key[0] == 0 and not os.path.basename(rec.path).lower().startswith((
                "ld-linux", "ld-musl", "libc.", "libpthread.", "libdl.", "librt.",
                "libm.", "libstdc++.", "libgcc_s.", "libglib-", "libgobject-", "libgio-")):
            # Installed != frequently used. Keep the loader/ABI foundation
            # first, then actual observed apps, then unused system payloads.
            key[0] = 1.5
        # Real recurring use outranks unused installations. Never promote
        # downloaded game content or bulk fallback media to executable priority.
        if hits > 0 and key[0] < 5:
            age_days = max(0.0, (time.time() - last_use) / 86400)
            frequency = min(32.0, hits) * (0.5 ** (age_days / 14.0))
            browser_kind = browser_cache_kind(rec.path.lower())
            repeated_use = 1.5 if browser_kind and browser_kind[1] == "http" else 0.5
            if frequency >= repeated_use:
                key[0] = min(key[0], 0.5 if not budget else 0.75)
                key[1] = -20000 - min(10000, frequency * 200)
                if budget:
                    key[2] = -last_use
        rows.append((rec, tuple(key), budget, unit))
    return rows


class InventoryDB:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.connection = sqlite3.connect(path, timeout=5)
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA cache_size=-16384")
        self.connection.execute("PRAGMA temp_store=FILE")
        self.connection.execute("PRAGMA wal_autocheckpoint=2048")
        version = self.connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, DB_SCHEMA):
            raise ValueError(f"unsupported inventory schema {version}")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                path BLOB PRIMARY KEY, parent BLOB NOT NULL,
                size INTEGER NOT NULL, stamp REAL NOT NULL, mode INTEGER NOT NULL,
                dev INTEGER NOT NULL, ino INTEGER NOT NULL,
                mtime_ns INTEGER NOT NULL, ctime_ns INTEGER NOT NULL,
                k0 REAL, k1 REAL, k2 REAL, k3 REAL, k4 REAL,
                budget TEXT NOT NULL DEFAULT '', unit BLOB NOT NULL DEFAULT X'',
                seen INTEGER NOT NULL DEFAULT 0, dir_token INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS file_priority ON files(k0,k1,k2,k3,k4,path);
            CREATE INDEX IF NOT EXISTS file_parent ON files(parent);
            CREATE INDEX IF NOT EXISTS file_inode ON files(dev,ino);
            CREATE INDEX IF NOT EXISTS file_budget ON files(budget,unit);
            CREATE TABLE IF NOT EXISTS usage (
                path BLOB PRIMARY KEY, hits REAL NOT NULL, last_use REAL NOT NULL,
                bucket INTEGER NOT NULL, app TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS usage_recency ON usage(last_use);
            CREATE TABLE IF NOT EXISTS todo (
                path BLOB PRIMARY KEY, dev INTEGER NOT NULL,
                stay INTEGER NOT NULL, active INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS visited (path BLOB PRIMARY KEY, generation INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS dirty (path BLOB PRIMARY KEY);
        """)
        self.connection.execute(f"PRAGMA user_version={DB_SCHEMA}")
        self.connection.execute("UPDATE todo SET active=0")
        self.connection.commit()
        os.chmod(path, 0o600)

    def meta(self, key, default=None):
        result = self.connection.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return json.loads(result[0]) if result else default

    def set_meta(self, key, value):
        self.connection.execute("INSERT OR REPLACE INTO meta VALUES (?,?)", (key, json.dumps(value)))

    def begin_scan(self, roots: list[str], cfg: dict, *, resume=True):
        fingerprint = hashlib.sha256(json.dumps(
            [roots, cfg.get("exclude_prefixes", []), cfg.get("stay_on_filesystem", True), POLICY_VERSION],
            sort_keys=True).encode()).hexdigest()
        if resume and self.meta("scan_pending", False) and self.meta("scan_fingerprint") == fingerprint:
            return self.meta("generation", 1)
        generation = int(self.meta("generation", 0)) + 1
        self.set_meta("generation", generation)
        self.set_meta("scan_pending", True)
        self.set_meta("scan_fingerprint", fingerprint)
        self.connection.execute("DELETE FROM todo")
        for root in roots:
            dev = safe_dev(root)
            if dev is not None:
                stay = bool(cfg.get("stay_on_filesystem", True) and not root_allows_cross_filesystem(root, cfg))
                self.add_directory(root, dev, stay)
        self.connection.commit()
        return generation

    def add_directory(self, path, dev, stay):
        previous = self.connection.execute("SELECT generation FROM visited WHERE path=?", (os.fsencode(path),)).fetchone()
        if previous and previous[0] == self.meta("generation", 0):
            return
        self.connection.execute("INSERT OR IGNORE INTO todo(path,dev,stay) VALUES (?,?,?)",
                                (os.fsencode(path), dev, int(stay)))

    def take_directories(self, count):
        rows = self.connection.execute("SELECT path,dev,stay FROM todo WHERE active=0 LIMIT ?", (count,)).fetchall()
        self.connection.executemany("UPDATE todo SET active=1 WHERE path=?", [(r[0],) for r in rows])
        return [(os.fsdecode(path), dev, bool(stay)) for path, dev, stay in rows]

    def remove_prefix(self, path):
        raw = os.fsencode(os.path.normpath(path))
        prefix = raw.rstrip(b"/") + b"/"
        end = prefix[:-1] + b"0"
        self.connection.execute("DELETE FROM files WHERE path=? OR (path>=? AND path<?)", (raw, prefix, end))
        self.connection.execute("DELETE FROM usage WHERE path=? OR (path>=? AND path<?)", (raw, prefix, end))

    def prepare(self, records, generation, *, force=False, dir_token=0):
        changed = []
        for rec in records:
            raw = os.fsencode(rec.path)
            row = self.connection.execute(
                "SELECT size,dev,ino,mtime_ns,ctime_ns FROM files WHERE path=?", (raw,)).fetchone()
            if not force and row == (rec.size, rec.dev, rec.ino, rec.mtime_ns, rec.ctime_ns):
                self.connection.execute("UPDATE files SET seen=?,dir_token=CASE WHEN ?<>0 THEN ? ELSE dir_token END WHERE path=?",
                                        (generation, dir_token, dir_token, raw))
                continue
            use = self.connection.execute("SELECT hits,last_use FROM usage WHERE path=?", (raw,)).fetchone()
            changed.append((rec, *(use or (0, 0))))
        return changed

    def store(self, rows, generation, dir_token=0):
        for rec, priority, budget, unit in rows:
            raw = os.fsencode(rec.path)
            if priority is None:
                self.connection.execute("DELETE FROM files WHERE path=?", (raw,))
                continue
            token = dir_token.get(os.path.dirname(rec.path), 0) if isinstance(dir_token, dict) else dir_token
            self.connection.execute("""INSERT INTO files VALUES
                (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET
                parent=excluded.parent,size=excluded.size,stamp=excluded.stamp,mode=excluded.mode,
                dev=excluded.dev,ino=excluded.ino,mtime_ns=excluded.mtime_ns,ctime_ns=excluded.ctime_ns,
                k0=excluded.k0,k1=excluded.k1,k2=excluded.k2,k3=excluded.k3,k4=excluded.k4,
                budget=excluded.budget,unit=excluded.unit,seen=excluded.seen,
                dir_token=CASE WHEN excluded.dir_token<>0 THEN excluded.dir_token ELSE files.dir_token END""", (
                    raw, os.fsencode(os.path.dirname(rec.path)), rec.size, rec.mtime, rec.mode,
                    rec.dev, rec.ino, rec.mtime_ns, rec.ctime_ns, *priority,
                    budget, os.fsencode(unit), generation, token))

    def observe(self, records: list[tuple[FileRec, str]], generation, dir_tokens=None):
        now = time.time()
        bucket = int(now // 300)
        changed = []
        for rec, app in records:
            raw = os.fsencode(rec.path)
            previous = self.connection.execute("SELECT hits,last_use,bucket FROM usage WHERE path=?", (raw,)).fetchone()
            if previous and previous[2] == bucket:
                continue
            hits = 1.0
            if previous:
                hits += previous[0] * (0.5 ** (max(0, now - previous[1]) / (14 * 86400)))
            hits = min(64.0, hits)
            self.connection.execute("INSERT OR REPLACE INTO usage VALUES (?,?,?,?,?)",
                                    (raw, hits, now, bucket, app))
            changed.append((rec, hits, now))
        self.store(classify_batch(changed), generation, dir_tokens or 0)
        return len(changed)

    def count(self):
        return self.connection.execute("SELECT count(*) FROM files").fetchone()[0]

    def refresh_usage_priorities(self, limit=256):
        """Decay old preferences daily in bounded batches, including unchanged files."""
        if time.time() - self.meta("last_rank_refresh", 0) < 86400:
            return 0
        cursor = bytes.fromhex(self.meta("rank_cursor", ""))
        rows = self.connection.execute("""SELECT f.path,f.size,f.stamp,f.mode,f.dev,f.ino,f.mtime_ns,f.ctime_ns,u.hits,u.last_use
            FROM usage u JOIN files f ON f.path=u.path WHERE u.path>? ORDER BY u.path LIMIT ?""", (cursor, limit)).fetchall()
        work = [(FileRec(os.fsdecode(row[0]), *row[1:8]), row[8], row[9]) for row in rows]
        for rec, priority, budget, unit in classify_batch(work):
            if priority is not None:
                self.connection.execute("UPDATE files SET k0=?,k1=?,k2=?,k3=?,k4=?,budget=?,unit=? WHERE path=?",
                                        (*priority, budget, os.fsencode(unit), os.fsencode(rec.path)))
        if rows:
            self.set_meta("rank_cursor", rows[-1][0].hex())
        else:
            self.set_meta("rank_cursor", "")
            self.set_meta("last_rank_refresh", time.time())
            # By this age even a formerly saturated frequency has decayed below
            # the promotion threshold. Ranking was reset before removing history.
            self.connection.execute("DELETE FROM usage WHERE last_use<?", (time.time() - 120 * 86400,))
        return len(rows)

    def trim_usage(self, maximum=250000):
        count = self.connection.execute("SELECT count(*) FROM usage").fetchone()[0]
        excess = min(256, max(0, count - maximum))
        if not excess:
            return 0
        rows = self.connection.execute("""SELECT u.path,f.size,f.stamp,f.mode,f.dev,f.ino,f.mtime_ns,f.ctime_ns
            FROM usage u LEFT JOIN files f ON f.path=u.path ORDER BY u.last_use LIMIT ?""", (excess,)).fetchall()
        work = [(FileRec(os.fsdecode(row[0]), *row[1:]), 0, 0) for row in rows if row[1] is not None]
        for rec, priority, budget, unit in classify_batch(work):
            if priority is not None:
                self.connection.execute("UPDATE files SET k0=?,k1=?,k2=?,k3=?,k4=? WHERE path=?",
                                        (*priority, os.fsencode(rec.path)))
        self.connection.executemany("DELETE FROM usage WHERE path=?", [(row[0],) for row in rows])
        return excess

    def publish(self, cfg: dict, roots: list[str], *, reason: str):
        """Stream from the priority index. No all-inventory Python list/sort."""
        total_ram = parse_meminfo()["MemTotal"]
        limit = min(parse_size(cfg.get("plan_budget_bytes")) or int(total_ram * 0.95),
                    int(total_ram * 1.25))
        max_files = int(cfg.get("plan_max_files", 350000 if total_ram > 20 * GIB else 120000))
        caps, file_caps = cache_budget_caps(cfg), cache_budget_file_caps(cfg)
        used, counts, units, inodes = {}, {}, {}, set()
        chosen_units = set()
        # This indexed aggregate only visits bounded game content, never every
        # inventory record before each selection as the old controller did.
        for unit, size in self.connection.execute(
                "SELECT unit,sum(size) FROM files WHERE budget='vrchat_content_cache' GROUP BY unit"):
            units[unit] = size
        path = STATE_PATH / "startup-plan.jsonl"
        fd, temp = tempfile.mkstemp(prefix="startup-plan.", dir=STATE_PATH)
        byte_count = count = 0
        digest = hashlib.sha256()
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                header = {"schema": 1, "policy": POLICY_VERSION, "created": time.time(),
                          "generation": uuid.uuid4().hex, "reason": reason}
                output.write(json.dumps(header) + "\n")
                query = "SELECT path,size,stamp,mode,dev,ino,mtime_ns,ctime_ns,k0,k1,k2,k3,k4,budget,unit FROM files ORDER BY k0,k1,k2,k3,k4,path"
                for row in self.connection.execute(query):
                    raw, size, stamp, mode, dev, ino, mtime_ns, ctime_ns, *tail = row
                    path_text = os.fsdecode(raw)
                    if not cache_path_allowed(path_text, cfg, roots):
                        continue
                    identity = (dev, ino)
                    if identity in inodes:
                        continue
                    cost = page_bytes(size)
                    if byte_count + cost > limit:
                        continue
                    priority, budget, unit = tuple(tail[:5]), tail[5], tail[6]
                    if budget:
                        budget_cost = cost
                        if budget == "vrchat_content_cache":
                            if unit not in chosen_units:
                                budget_cost = units.get(unit, cost)
                            else:
                                budget_cost = 0
                        if used.get(budget, 0) + budget_cost > caps.get(budget, limit):
                            continue
                        if counts.get(budget, 0) >= file_caps.get(budget, max_files):
                            continue
                        used[budget] = used.get(budget, 0) + budget_cost
                        counts[budget] = counts.get(budget, 0) + 1
                        if budget == "vrchat_content_cache":
                            chosen_units.add(unit)
                    inodes.add(identity)
                    rec = FileRec(path_text, size, stamp, mode, dev, ino, mtime_ns, ctime_ns,
                                   priority, budget)
                    line = json.dumps(record_to_list(rec), ensure_ascii=True, separators=(",", ":")) + "\n"
                    digest.update(line.encode("utf-8"))
                    output.write(line)
                    byte_count += cost
                    count += 1
                    if count >= max_files or byte_count >= limit:
                        break
                output.flush()
                os.fsync(output.fileno())
            invalid = RUNTIME_PATH / "plan-invalid.json"
            if self.meta("plan_digest") == digest.hexdigest() and path.exists() and not invalid.exists():
                os.unlink(temp)
                header["generation"] = self.meta("plan_generation", header["generation"])
            else:
                os.replace(temp, path)
                directory = os.open(STATE_PATH, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                self.set_meta("plan_digest", digest.hexdigest())
                self.set_meta("plan_generation", header["generation"])
                invalid.unlink(missing_ok=True)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        return {"plan_files": count, "plan_bytes": byte_count, "plan_generation": header["generation"]}


class DirectoryScanner:
    """Bounded I/O pipeline. SQLite retains pending directories across reboots."""
    def __init__(self, cfg: dict, roots: list[str], workers: int):
        self.cfg, self.roots = cfg, roots
        self.tasks = queue.Queue(maxsize=workers * 2)
        self.results = queue.Queue(maxsize=workers * 4)
        self.stop = threading.Event()
        self.paused = threading.Event()
        self.workers = workers
        self.active = set()
        self.threads = [threading.Thread(target=self.run, daemon=True, name=f"inventory-io-{i}")
                        for i in range(workers)]
        for thread in self.threads:
            thread.start()

    def send(self, value):
        while not self.stop.is_set():
            try:
                self.results.put(value, timeout=0.25)
                return
            except queue.Full:
                pass

    def run(self):
        while not self.stop.is_set():
            try:
                directory, device, stay = self.tasks.get(timeout=0.25)
            except queue.Empty:
                continue
            records, children = [], []
            success = False
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        while self.paused.is_set() and not self.stop.is_set():
                            self.stop.wait(0.25)
                        if self.stop.is_set():
                            break
                        path = entry.path
                        if not cache_path_allowed(path, self.cfg, self.roots):
                            continue
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if should_prune_dir(path.lower()):
                                    continue
                                if stay and entry.stat(follow_symlinks=False).st_dev != device:
                                    continue
                                children.append((path, device, stay))
                            elif entry.is_file(follow_symlinks=False):
                                st = entry.stat(follow_symlinks=False)
                                maximum = parse_size(self.cfg.get("vmtouch_max_file_size", "128G"))
                                if (stay and st.st_dev != device) or (maximum and st.st_size > maximum):
                                    continue
                                rec = stat_record(path, st)
                                if rec is not None:
                                    records.append(rec)
                        except OSError:
                            continue
                        if len(records) + len(children) >= 256:
                            self.send(("batch", directory, records, children))
                            records, children = [], []
                    success = not self.stop.is_set()
            except FileNotFoundError:
                success = True
            except OSError:
                # Inaccessible/removable roots must not delete good saved data.
                pass
            if records or children:
                self.send(("batch", directory, records, children))
            self.send(("done", directory, success, None))
            self.tasks.task_done()

    def close(self):
        self.stop.set()


def compact_prefixes(paths):
    kept = []
    for path in sorted(set(paths), key=lambda value: (len(value), value)):
        if not any(path_is_under(path, root) for root in kept):
            kept.append(path)
    return kept


def bootstrap_paths(cfg: dict, roots: list[str]) -> list[str]:
    """Small code/runtime discovery starts before the broad inventory."""
    wanted = ["/usr/bin", "/usr/libexec", "/usr/lib", "/usr/lib64", "/opt",
              "/usr/share/applications", "/usr/share/fonts", "/usr/share/glib-2.0",
              "/var/lib/flatpak/app", "/var/lib/flatpak/runtime"]
    for home in iter_home_dirs():
        wanted.extend(str(home / child) for child in (
            ".local/share/flatpak/app", ".local/share/flatpak/runtime", ".local/bin",
            ".config/mozilla", ".mozilla", ".config/obs-studio", ".config/vesktop",
            ".config/discord", ".config/google-chrome", ".config/chromium",
            ".cache/mozilla", ".cache/google-chrome", ".cache/chromium"))
        for root in (home / ".steam/root", home / ".local/share/Steam", home / ".steam/debian-installation"):
            for child in ("ubuntu12_64", "ubuntu12_32", "resource", "config", "steamapps/common/VRChat"):
                wanted.append(os.path.realpath(root / child))
    return [path for path in compact_prefixes(wanted)
            if os.path.isdir(path) and cache_path_allowed(path, cfg, roots)]


def run_planner() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    _, cfg = load_config()
    roots = normalized_roots(cfg)
    cfg["_resolved_roots"] = roots
    STATE_PATH.mkdir(parents=True, exist_ok=True, mode=0o700)
    db_path = STATE_PATH / "inventory.sqlite3"
    try:
        db = InventoryDB(db_path)
    except (sqlite3.DatabaseError, ValueError):
        logging.exception("saved inventory could not be opened; rebuilding metadata")
        suffix = ".unreadable-" + str(int(time.time()))
        for extension in ("", "-wal", "-shm"):
            source = Path(str(db_path) + extension)
            if source.exists():
                source.rename(str(source) + suffix)
        db = InventoryDB(db_path)
    # State survives interruption at directory granularity. Restat selected
    # files in the supervisor before warming, then reconcile the rest here.
    first_install = not (STATE_PATH / "startup-plan.jsonl").exists()
    generation = db.begin_scan(roots, cfg)
    if first_install:
        # Put useful small discovery roots ahead of the broad filesystem walk.
        original = db.connection.execute("SELECT path,dev,stay FROM todo").fetchall()
        db.connection.execute("DELETE FROM todo")
        for path in bootstrap_paths(cfg, roots):
            dev = safe_dev(path)
            if dev is not None:
                db.add_directory(path, dev, True)
        for raw, dev, stay in original:
            db.add_directory(os.fsdecode(raw), dev, stay)
    db.connection.commit()
    scanner = DirectoryScanner(cfg, roots, resolve_scan_worker_count(cfg))
    observer = UsageObserver(cfg, roots)
    if cfg.get("learning_enabled", True):
        observer.start()
    watcher = Watcher()
    watcher_retry_at = 0.0
    watcher_failures = 0
    try:
        cpus = len(os.sched_getaffinity(0))
    except AttributeError:
        cpus = os.cpu_count() or 1
    classifier_count = min(max(1, cpus // 4), max(1, int(cfg.get("classification_worker_max", 4))))
    pool = concurrent.futures.ProcessPoolExecutor(
        max_workers=classifier_count, mp_context=multiprocessing.get_context("spawn"))
    futures = {}  # bounded to a few batches, never millions of Python objects
    directory_pending = {}
    directory_finished = {}
    directory_tokens = {}
    refresh_again = set()
    reclassify = db.meta("policy_version") != POLICY_VERSION
    last_publish = last_commit = last_status = 0.0
    changed = 0
    scanned = 0
    errors = 0
    last_full_scan = db.meta("last_full_scan", 0)
    inventory_count = db.count()
    last_count = time.monotonic()
    plan_info = {"plan_files": 0, "plan_bytes": 0}
    phase = "reconciling" if not first_install else "bootstrap"
    scan_active = True
    rescan_requested = False
    last_event_refresh = time.monotonic()
    last_usage_trim = 0.0
    last_root_refresh = time.monotonic()
    root_devices = [(path, safe_dev(path)) for path in roots]
    started = time.monotonic()
    try:
        while RUNNING:
            now = time.monotonic()
            if (RUNTIME_PATH / "plan-invalid.json").exists():
                changed += 1
                last_publish = 0
            control = read_json(RUNTIME_PATH / "pressure.json", {}) or {}
            paused = bool(control.get("pause_discovery", False))
            if time.time() - control.get("timestamp", 0) > 10:
                paused = False
            (scanner.paused.set if paused else scanner.paused.clear)()

            if not paused and now - last_root_refresh >= 300:
                last_root_refresh = now
                discovered = normalized_roots(cfg)
                devices = [(path, safe_dev(path)) for path in discovered]
                if devices != root_devices:
                    roots, root_devices = discovered, devices
                    cfg["_resolved_roots"] = roots
                    scanner.roots = roots
                    _SCAN_STORAGE_PROFILE_CACHE.clear()
                    observer.close()
                    observer = UsageObserver(cfg, roots)
                    if cfg.get("learning_enabled", True):
                        observer.start()
                    watcher.stop()
                    watcher_retry_at = 0
                    rescan_requested = True
                    changed += 1
                    logging.info("application/storage roots changed; scheduling reconciliation")

            if watcher.dead() and now >= watcher_retry_at:
                if watcher.proc is not None:
                    watcher_failures += 1
                    rescan_requested = True
                try:
                    watcher.start(cfg)
                except OSError:
                    logging.exception("filesystem watcher unavailable; scheduled reconciliation remains active")
                    watcher_failures += 1
                watcher_retry_at = now + min(300, 5 * (2 ** min(watcher_failures, 6)))
            if watcher.needs_resync():
                watcher.mark_resynced()
                rescan_requested = True

            # Commit finished CPU work before considering a directory complete.
            for future, directory in list(futures.items()):
                if not future.done():
                    continue
                try:
                    rows = future.result()
                    db.store(rows, generation, directory_tokens.get(directory, 0))
                    changed += len(rows)
                except Exception:
                    logging.exception("classification batch failed; directory will be retried")
                    directory_finished[directory] = False
                    rescan_requested = True
                    errors += 1
                directory_pending[directory] = max(0, directory_pending.get(directory, 0) - 1)
                del futures[future]

            for directory, success in list(directory_finished.items()):
                if directory_pending.get(directory, 0):
                    continue
                raw = os.fsencode(directory)
                if success:
                    db.connection.execute("DELETE FROM files WHERE parent=? AND dir_token<>?",
                                          (raw, directory_tokens.get(directory, 0)))
                else:
                    # Preserve old entries below a temporarily unavailable path.
                    prefix = raw.rstrip(b"/") + b"/"
                    db.connection.execute("UPDATE files SET seen=? WHERE path>=? AND path<?",
                                          (generation, prefix, prefix[:-1] + b"0"))
                    errors += 1
                db.connection.execute("INSERT OR REPLACE INTO visited VALUES (?,?)", (raw, generation))
                db.connection.execute("DELETE FROM todo WHERE path=?", (raw,))
                scanner.active.discard(directory)
                directory_pending.pop(directory, None)
                directory_tokens.pop(directory, None)
                del directory_finished[directory]
                if directory in refresh_again:
                    refresh_again.remove(directory)
                    db.connection.execute("DELETE FROM visited WHERE path=?", (raw,))
                    dev = safe_dev(directory)
                    if dev is not None:
                        db.add_directory(directory, dev, True)

            if not paused and len(futures) < classifier_count * 3:
                # Keep a short work slice so learning, checkpoints and watcher
                # recovery continue during a multi-million-file first scan.
                deadline = now + 0.05
                while time.monotonic() < deadline and len(futures) < classifier_count * 3:
                    try:
                        kind, directory, first, second = scanner.results.get_nowait()
                    except queue.Empty:
                        break
                    if kind == "done":
                        directory_finished[directory] = bool(first)
                    else:
                        records, children = first, second
                        scanned += len(records)
                        for path, dev, stay in children:
                            db.add_directory(path, dev, stay)
                        work = db.prepare(records, generation, force=reclassify,
                                          dir_token=directory_tokens.get(directory, 0))
                        if work:
                            future = pool.submit(classify_batch, work)
                            futures[future] = directory
                            directory_pending[directory] = directory_pending.get(directory, 0) + 1
                room = scanner.workers - len(scanner.active)
                if room > 0:
                    for item in db.take_directories(room):
                        scanner.active.add(item[0])
                        directory_tokens[item[0]] = time.time_ns()
                        scanner.tasks.put_nowait(item)

            # Learning continues on warm launches. Events are deduplicated into
            # five-minute buckets so polling/noisy apps cannot buy all the cache.
            observations = observer.take(256)
            if observations:
                changed += db.observe(observations, generation, directory_tokens)
            if not paused:
                changed += db.refresh_usage_priorities()
                if now - last_usage_trim >= 60:
                    trimmed = db.trim_usage(max(1000, int(cfg.get("learning_max_files", 250000))))
                    changed += trimmed
                    if not trimmed:
                        last_usage_trim = now

            refresh_interval = min(60, max(5, float(cfg.get("incremental_rescan_interval_seconds", 30))))
            if not paused and now - last_event_refresh >= refresh_interval:
                last_event_refresh = now
                changes = watcher.take_changes()
                directories, removed, files = [], [], set()
                for events, path in changes:
                    kinds = set(events.split(","))
                    if "ISDIR" in kinds:
                        # Coalesced create+delete+rename events describe a path,
                        # not an ordered transaction. Reconcile its current state.
                        if os.path.isdir(path):
                            directories.append(path)
                        else:
                            removed.append(path)
                    else:
                        files.add(path)
                for path in compact_prefixes(removed):
                    db.remove_prefix(path)
                    changed += 1
                for path in compact_prefixes(directories):
                    if cache_path_allowed(path, cfg, roots) and os.path.isdir(path):
                        db.connection.execute("DELETE FROM visited WHERE path=?", (os.fsencode(path),))
                        if path in scanner.active:
                            refresh_again.add(path)
                        dev = safe_dev(path)
                        if dev is not None:
                            db.add_directory(path, dev, True)
                db.connection.executemany("INSERT OR IGNORE INTO dirty VALUES (?)", [(os.fsencode(path),) for path in files])
                changed += len(changes)

            if not paused:
                dirty = db.connection.execute("SELECT path FROM dirty LIMIT 256").fetchall()
                refresh = []
                for (raw,) in dirty:
                    path = os.fsdecode(raw)
                    rec = stat_record(path)
                    if rec and cache_path_allowed(path, cfg, roots):
                        refresh.append(rec)
                    else:
                        db.connection.execute("DELETE FROM files WHERE path=?", (raw,))
                db.store(classify_batch(db.prepare(refresh, generation)), generation, directory_tokens)
                db.connection.executemany("DELETE FROM dirty WHERE path=?", dirty)
                changed += len(dirty)

            pending = db.connection.execute("SELECT count(*) FROM todo").fetchone()[0]
            if scan_active and pending == 0 and not futures and not scanner.active:
                db.connection.execute("DELETE FROM files WHERE seen<>?", (generation,))
                last_full_scan = time.time()
                db.set_meta("last_full_scan", last_full_scan)
                db.set_meta("scan_pending", False)
                db.set_meta("policy_version", POLICY_VERSION)
                db.connection.commit()
                scan_active = False
                reclassify = False
                phase = "watching"
                changed += 1
                logging.info("inventory reconciliation complete: %d files examined in %.2fs", scanned, now - started)

            periodic = max(300, float(cfg.get("full_rescan_interval_seconds", 86400)))
            if not scan_active and not pending and (rescan_requested or time.time() - last_full_scan > periodic):
                generation = db.begin_scan(roots, cfg, resume=False)
                scan_active = True
                rescan_requested = False
                phase = "reconciling"
                started = now

            publish_interval = 5 if first_install and now - started < 60 else 30
            if changed and not paused and now - last_publish >= publish_interval:
                db.connection.commit()
                plan_info = db.publish(cfg, roots, reason=phase)
                last_publish = now
                changed = 0
            if now - last_commit > 2:
                db.connection.commit()
                last_commit = now
            if now - last_count > 30:
                inventory_count = db.count()
                last_count = now
            if now - last_status >= 1:
                atomic_json(RUNTIME_PATH / "planner-status.json", {
                    "timestamp": time.time(), "pid": os.getpid(), "phase": "paused" if paused else phase,
                    "inventory_files": inventory_count, "scanned_files": scanned,
                    "pending_directories": pending, "scan_workers": scanner.workers,
                    "classification_workers": classifier_count, "last_scan_epoch": last_full_scan,
                    "watcher_mode": watcher.mode, "watcher_failures": watcher_failures,
                    "pending_fs_events": watcher.pending_count(), "learning_mode": observer.mode,
                    "learning_events": observer.events, "learning_dropped": observer.dropped,
                    "learning_error": observer.last_error, "scan_errors": errors, **plan_info,
                    "include_roots": roots, "storage_profile": resolve_scan_storage_profile(cfg),
                })
                last_status = now
            time.sleep(0.02 if pending or futures else 0.2)
    finally:
        scanner.close()
        observer.close()
        watcher.stop()
        # Never wait indefinitely for blocked filesystem I/O on shutdown.
        pool.shutdown(wait=False, cancel_futures=True)
        db.connection.commit()
        db.connection.close()
    return 0

class UsageObserver:
    """Bounded, notification-only learning, independent of page-cache misses.

    fanotify supplies ordinary opens, including warm opens. /proc maps supplies
    executable/library mappings that access notifications cannot fully describe.
    No permission events, ptrace, browser hooks, URLs, or file contents are used.
    """
    def __init__(self, cfg: dict, roots: list[str]):
        self.cfg, self.roots = cfg, roots
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.pending = {}
        self.processes = {}
        self.seen_processes = {}
        self.mode = "process-maps"
        self.dropped = 0
        self.events = 0
        self.last_error = ""
        self.fd = -1
        self.limit = int(cfg.get("learning_pending_max", 32768))
        self.threads = []
        self.negative_pids = {}
        self.mount_cache = {}
        self.ignored = {"pgrep", "pactl", "busctl", "grep", "cat", "sleep", "tee", "find",
                        "strace", "opensnoop-bpfcc", "vmtouch", "inotifywait", "fsnotifywait",
                        "iostat", "pidstat", "vmstat", "journalctl", "stat", "readlink"}

    def add(self, rec: FileRec, app: str):
        if not cache_path_allowed(rec.path, self.cfg, self.roots):
            return
        if not record_device_allowed(rec, self.cfg, self.roots):
            return
        maximum = parse_size(self.cfg.get("vmtouch_max_file_size", "128G")) or 128 * GIB
        if rec.size > maximum:
            return
        with self.lock:
            if len(self.pending) >= self.limit and rec.path not in self.pending:
                self.dropped += 1
                return
            self.pending[rec.path] = (rec, app)
            self.events += 1

    def take(self, maximum=2048):
        with self.lock:
            keys = list(self.pending)[:maximum]
            return [self.pending.pop(key) for key in keys]

    def application_for_pid(self, pid):
        app = self.processes.get(pid)
        if app:
            return app
        now = time.monotonic()
        if self.negative_pids.get(pid, 0) > now:
            return None
        try:
            base = f"/proc/{pid}"
            uid = os.stat(base).st_uid
            if 1000 <= uid < 65534:
                exe = os.readlink(base + "/exe")
                if os.path.basename(exe) not in self.ignored and not exe.endswith(" (deleted)"):
                    app = exe.encode("utf-8", "replace").decode("utf-8")
                    self.processes[pid] = app
                    return app
        except OSError:
            pass
        if len(self.negative_pids) >= 8192:
            self.negative_pids.clear()
        self.negative_pids[pid] = now + 3
        return None

    def start(self):
        thread = threading.Thread(target=self.sample_processes, daemon=True, name="application-maps")
        thread.start()
        self.threads.append(thread)
        if self.cfg.get("learn_file_opens", True):
            thread = threading.Thread(target=self.open_events, daemon=True, name="application-opens")
            thread.start()
            self.threads.append(thread)

    def sample_processes(self):
        while not self.stop.is_set():
            current = {}
            try:
                entries = list(os.scandir("/proc"))
            except OSError:
                entries = []
            for entry in entries:
                if not entry.name.isdigit() or int(entry.name) == os.getpid():
                    continue
                pid = int(entry.name)
                base = entry.path
                try:
                    uid = entry.stat().st_uid
                    if uid < 1000 or uid >= 65534:
                        continue
                    exe = os.readlink(base + "/exe")
                    name = os.path.basename(exe)
                    if name in self.ignored or exe.endswith(" (deleted)"):
                        continue
                    stat_text = Path(base + "/stat").read_text()
                    start = stat_text.rsplit(")", 1)[1].split()[19]
                    identity = (pid, start)
                    app = exe.encode("utf-8", "replace").decode("utf-8")
                    # Flatpak process paths are inside a mount namespace. The
                    # application ID is more stable than /app/bin/<executable>.
                    try:
                        with open(base + "/root/.flatpak-info", encoding="utf-8", errors="replace") as info:
                            for line in info:
                                if line.startswith("name="):
                                    app = "flatpak:" + line[5:].strip()
                                    break
                    except OSError:
                        pass
                    current[pid] = app
                    last = self.seen_processes.get(identity, 0)
                    now = time.monotonic()
                    if now - last < 30:
                        continue
                    self.seen_processes[identity] = now
                    mapped = set()
                    with open(base + "/maps", encoding="utf-8", errors="surrogateescape") as maps:
                        for index, line in enumerate(maps):
                            if index >= 32768:
                                break
                            parts = line.split(None, 5)
                            if len(parts) < 6:
                                continue
                            path = parts[5].rstrip("\n")
                            if not path.startswith("/") or path.endswith(" (deleted)") or path in mapped:
                                continue
                            mapped.add(path)
                            # Use proc's mapping symlink to resolve the actual
                            # host file, not a guessed /app or /run/host prefix.
                            actual = path
                            try:
                                actual = os.readlink(base + "/map_files/" + parts[0])
                            except OSError:
                                pass
                            try:
                                wanted_ino = int(parts[4])
                                major, minor = (int(x, 16) for x in parts[3].split(":"))
                                wanted_dev = os.makedev(major, minor)
                                rec = stat_record(actual)
                                if rec and (rec.dev, rec.ino) == (wanted_dev, wanted_ino):
                                    self.add(rec, app)
                                else:
                                    # Paths reported relative to sandbox roots
                                    # are resolved using mountinfo only when the
                                    # translated file has the same device/inode.
                                    translated = self.host_path(pid, path, wanted_dev, wanted_ino)
                                    if translated:
                                        rec = stat_record(translated)
                                        if rec:
                                            self.add(rec, app)
                            except (OSError, ValueError):
                                continue
                except (OSError, ValueError, IndexError):
                    continue
            self.processes = current
            alive = set(current)
            self.seen_processes = {key: value for key, value in self.seen_processes.items() if key[0] in alive}
            self.stop.wait(max(0.5, float(self.cfg.get("process_learning_interval_seconds", 2))))

    @staticmethod
    def unescape_mount(value):
        return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)

    def host_path(self, pid, path, dev, ino):
        try:
            candidates = []
            cached = self.mount_cache.get(pid)
            now = time.monotonic()
            if cached is None or now - cached[0] > 5:
                with open(f"/proc/{pid}/mountinfo", encoding="utf-8", errors="surrogateescape") as source:
                    foreign = [line.split() for line in source]
                with open("/proc/self/mountinfo", encoding="utf-8", errors="surrogateescape") as source:
                    host = [line.split() for line in source]
                if len(self.mount_cache) >= 1024:
                    self.mount_cache.clear()
                cached = (now, foreign, host)
                self.mount_cache[pid] = cached
            device = f"{os.major(dev)}:{os.minor(dev)}"
            for fields in cached[1]:
                if len(fields) < 6 or fields[2] != device:
                    continue
                mount = self.unescape_mount(fields[4])
                root = self.unescape_mount(fields[3])
                if not path_is_under(path, mount):
                    continue
                coordinate = os.path.normpath(os.path.join(root, os.path.relpath(path, mount)))
                candidates.append((len(mount), coordinate))
                # Both namespaces may mount a btrfs subvolume or bind root.
                # Translate filesystem coordinates through the host's mounts.
                for our_fields in cached[2]:
                    if len(our_fields) < 6 or our_fields[2] != device:
                        continue
                    our_root = self.unescape_mount(our_fields[3])
                    our_mount = self.unescape_mount(our_fields[4])
                    if path_is_under(coordinate, our_root):
                        candidate = os.path.normpath(os.path.join(our_mount, os.path.relpath(coordinate, our_root)))
                        candidates.append((len(mount), candidate))
            for _, candidate in sorted(candidates, reverse=True):
                rec = stat_record(candidate)
                if rec and (rec.dev, rec.ino) == (dev, ino):
                    return candidate
        except (OSError, ValueError):
            pass
        return None

    def setup_fanotify(self):
        libc = ctypes.CDLL(None, use_errno=True)
        init, mark = libc.fanotify_init, libc.fanotify_mark
        init.argtypes = [ctypes.c_uint, ctypes.c_uint]
        init.restype = ctypes.c_int
        mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
        mark.restype = ctypes.c_int
        fd = init(0x1 | 0x2, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_LARGEFILE", 0))
        if fd < 0:
            raise OSError(ctypes.get_errno(), "fanotify_init")
        marked = set()
        try:
            for root in self.roots:
                dev = safe_dev(root)
                if dev in marked:
                    continue
                # Notification events only: FAN_OPEN | FAN_OPEN_EXEC. Older
                # kernels can still supply ordinary opens without OPEN_EXEC.
                for mask in (0x20 | 0x1000, 0x20):
                    if mark(fd, 0x1 | 0x100, mask, -100, os.fsencode(root)) == 0:
                        marked.add(dev)
                        break
            if not marked:
                raise OSError(ctypes.get_errno(), "no filesystem supports open notifications")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def open_events(self):
        try:
            fd = self.setup_fanotify()
        except (OSError, AttributeError) as error:
            self.last_error = str(error)
            logging.info("file-open learning unavailable; process-map learning remains active: %s", error)
            return
        self.fd = fd
        self.mode = "fanotify-opens+process-maps"
        metadata = struct.Struct("=IBBHQii")
        try:
            while not self.stop.is_set():
                if not select.select([fd], [], [], 0.5)[0]:
                    continue
                try:
                    data = os.read(fd, 65536)
                except BlockingIOError:
                    continue
                offset = 0
                while offset + metadata.size <= len(data):
                    length, version, _, metadata_length, mask, file_fd, pid = metadata.unpack_from(data, offset)
                    if length < metadata.size or offset + length > len(data) or version != 3:
                        raise ValueError("unsupported fanotify event layout")
                    offset += length
                    if mask & 0x4000:  # FAN_Q_OVERFLOW
                        self.dropped += 1
                    if file_fd < 0:
                        continue
                    try:
                        app = self.application_for_pid(pid)
                        if app:
                            path = os.readlink(f"/proc/self/fd/{file_fd}")
                            if not path.endswith(" (deleted)"):
                                st = os.fstat(file_fd)
                                rec = stat_record(path)
                                if rec is None or (rec.dev, rec.ino) != (st.st_dev, st.st_ino):
                                    path = self.host_path(pid, path, st.st_dev, st.st_ino)
                                    rec = stat_record(path) if path else None
                                if rec:
                                    self.add(rec, app)
                    except (OSError, ValueError):
                        # An individual file/process can disappear between the
                        # notification and lookup; learning must keep running.
                        continue
                    finally:
                        os.close(file_fd)
        except (OSError, ValueError) as error:
            self.last_error = str(error)
            logging.warning("file-open learning stopped; using process maps: %s", error)
        finally:
            os.close(fd)
            self.fd = -1
            self.mode = "process-maps"

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=1)

class PlanReader:
    def __init__(self, cfg, roots):
        self.cfg, self.roots = cfg, roots
        self.messages = queue.Queue(maxsize=8)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True, name="startup-plan-validation")
        self.thread.start()

    def put(self, message):
        while not self.stop.is_set():
            try:
                self.messages.put(message, timeout=0.25)
                return
            except queue.Full:
                pass

    def run(self):
        last_identity = None
        path = STATE_PATH / "startup-plan.jsonl"
        while not self.stop.is_set():
            try:
                st = path.stat()
                identity = (st.st_ino, st.st_mtime_ns, st.st_size)
                if identity == last_identity:
                    self.stop.wait(0.5)
                    continue
                with path.open(encoding="utf-8") as source:
                    header = json.loads(source.readline(16384))
                    if header.get("schema") != 1:
                        raise ValueError("unsupported startup plan")
                    self.put(("begin", header))
                    batch, skipped, seen = [], 0, set()
                    index = 0
                    while True:
                        line = source.readline(65537)
                        if not line:
                            break
                        if self.stop.is_set():
                            return
                        if index >= int(self.cfg.get("plan_max_files", 350000)):
                            break
                        index += 1
                        if len(line) > 65536:
                            raise ValueError("oversized startup plan record")
                        saved = record_from_list(json.loads(line))
                        if not cache_path_allowed(saved.path, self.cfg, self.roots):
                            skipped += 1
                            continue
                        actual = stat_record(saved.path)
                        if actual is None or (actual.dev, actual.ino) in seen or not record_device_allowed(actual, self.cfg, self.roots):
                            skipped += 1
                            continue
                        if record_key(actual) != record_key(saved) or header.get("policy") != POLICY_VERSION:
                            priority = selection_sort_key(actual)
                            if priority is None:
                                skipped += 1
                                continue
                            saved = FileRec(actual.path, actual.size, actual.mtime, actual.mode,
                                            actual.dev, actual.ino, actual.mtime_ns, actual.ctime_ns,
                                            tuple(priority[:5]), cache_budget_key(actual) or "")
                        seen.add((actual.dev, actual.ino))
                        batch.append(saved)
                        if len(batch) >= 512:
                            self.put(("batch", batch))
                            batch = []
                    if batch:
                        self.put(("batch", batch))
                    self.put(("end", {"skipped": skipped, **header}))
                last_identity = identity
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError, KeyError) as error:
                atomic_json(RUNTIME_PATH / "plan-invalid.json", {"timestamp": time.time(), "reason": str(error)})
                self.put(("error", str(error)))
                self.stop.wait(5)
            self.stop.wait(0.5)


def choose_candidates(records, budget, cfg):
    total = 0
    selected = []
    used = {}
    counts = {}
    caps, file_caps = cache_budget_caps(cfg), cache_budget_file_caps(cfg)
    maximum = parse_size(cfg.get("vmtouch_max_file_size", "128G"))
    for rec in records:
        if maximum is not None and rec.size > maximum:
            continue
        cost = page_bytes(rec.size)
        if total + cost > budget:
            continue
        if rec.budget:
            if used.get(rec.budget, 0) + cost > caps.get(rec.budget, budget):
                continue
            if counts.get(rec.budget, 0) >= file_caps.get(rec.budget, 350000):
                continue
            used[rec.budget] = used.get(rec.budget, 0) + cost
            counts[rec.budget] = counts.get(rec.budget, 0) + 1
        selected.append(rec)
        total += cost
    return selected


def planner_command():
    return [sys.executable, str(Path(__file__).resolve()), "--planner", "--config", str(CONFIG_PATH),
            "--state-dir", str(STATE_PATH), "--runtime-dir", str(RUNTIME_PATH)]


def run_supervisor() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    STATE_PATH.mkdir(parents=True, exist_ok=True, mode=0o700)
    RUNTIME_PATH.mkdir(parents=True, exist_ok=True, mode=0o755)
    # Refuse a duplicate controller even when invoked outside systemd.
    lock_file = open(RUNTIME_PATH / "controller.lock", "a")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        logging.error("another RAMCache supervisor already owns this runtime directory")
        return 1
    config_text, cfg = load_config()
    roots = normalized_roots(cfg)
    cfg["_resolved_roots"] = roots
    storage_profile = resolve_scan_storage_profile(cfg)
    ensure_memlock_limit(parse_meminfo()["MemTotal"], cfg)
    # vmtouch holds mappings, not one supervisor fd per inventory entry.
    reader = PlanReader(cfg, roots)
    planner = subprocess.Popen(planner_command(), start_new_session=True)
    planner_started = time.monotonic()
    planner_retry = 0.0
    planner_failures = 0
    policy = PressurePolicy()
    io_activity = IOActivity()
    io_busy = False
    last_io_sample = 0.0
    workers = []
    retired = []
    records = []
    incoming = None
    plan_generation = ""
    pending_chunks = deque()
    failed_until = {}
    failures = 0
    warning_count = 0
    last_error = ""
    plan_skipped = 0
    last_reconcile = last_status = last_config = 0.0
    last_budget = 0
    plan_changed = False
    validated = False
    started = time.monotonic()
    first_warm = None
    loading_peak = 0
    try:
        while RUNNING:
            now = time.monotonic()
            if now - last_io_sample >= 1:
                io_busy = io_activity.busy(now)
                last_io_sample = now
            reap_workers(retired)
            meminfo = parse_meminfo()
            owned_locked = 0
            inflight = 0
            for worker in list(workers):
                locked = worker.locked
                if not worker.ready.is_set() or now - worker.last_sample >= 1:
                    locked, _ = process_memory(worker.proc.pid)
                    worker.last_sample = now
                if locked > worker.locked:
                    worker.last_progress = now
                worker.locked = locked
                if worker.proc.poll() is not None or worker.failed.is_set():
                    workers.remove(worker)
                    signal_worker(worker)
                    retired.append((now, worker))
                    failures += 1
                    last_error = worker.diagnostic or f"cache worker exited ({worker.proc.returncode})"
                    logging.warning("%s; retaining healthy cache workers", last_error)
                    retry = now + min(300, max(5, float(cfg.get("worker_retry_seconds", 30))))
                    for rec in worker.records:
                        failed_until[record_key(rec)] = retry
                    plan_changed = True
                    continue
                ready = worker.ready.is_set()
                if ready and not worker.acknowledged_at:
                    worker.acknowledged_at = now
                if ready and worker.warnings:
                    warning_count += worker.warnings
                    last_error = worker.diagnostic
                    logging.warning("cache worker reported %d skipped/error entries: %s", worker.warnings, last_error)
                    worker.warnings = 0
                if ready and worker.reported_pages * PAGE_SIZE != worker.requested:
                    # The worker acknowledged completion, so missing pages are
                    # failed/skipped work, never phantom outstanding I/O.
                    worker.requested = worker.reported_pages * PAGE_SIZE
                    worker.failed.set()
                    worker.diagnostic = worker.diagnostic or "cache worker acknowledged fewer pages than requested; retrying this chunk"
                if not ready:
                    # Reserve the complete loading chunk until acknowledgement;
                    # VmLck alone is not an I/O-completion signal.
                    inflight += worker.requested
                    timeout = max(30, float(cfg.get("worker_progress_timeout_seconds", 120)))
                    if now - worker.last_progress > timeout:
                        worker.failed.set()
                        worker.diagnostic = "cache worker made no progress before its deadline"
                elif (now - worker.acknowledged_at > 10
                      and locked < worker.reported_pages * PAGE_SIZE):
                    worker.failed.set()
                    worker.diagnostic = "a loaded mapping lost locked pages; revalidating this worker"
                owned_locked += locked
            own_anon = process_memory(os.getpid())[1]
            if planner.poll() is None:
                own_anon += process_memory(planner.pid)[1]
            release, pause = policy.evaluate(meminfo, cfg, owned_locked, own_anon)
            if release:
                target = max(0, owned_locked - release)
                # Signal all chosen workers before waiting for any exit. The
                # main loop never waits on a slow disk or blocked feeder.
                workers.sort(key=lambda item: item.priority)
                while workers and owned_locked > target:
                    worker = workers.pop()
                    owned_locked -= worker.locked
                    signal_worker(worker)
                    retired.append((now, worker))
                pending_chunks.clear()
                plan_changed = True

            # Stream useful validated records immediately, without waiting for
            # the rest of the saved list or the background inventory.
            for _ in range(16):
                try:
                    kind, payload = reader.messages.get_nowait()
                except queue.Empty:
                    break
                if kind == "begin":
                    incoming = []
                elif kind == "batch" and incoming is not None:
                    incoming.extend(payload)
                    if not validated:
                        records = incoming
                        plan_changed = True
                elif kind == "end" and incoming is not None:
                    records = incoming
                    incoming = None
                    plan_generation = payload["generation"]
                    plan_skipped = payload["skipped"]
                    plan_changed = True
                    validated = True
                elif kind == "error":
                    incoming = None
                    last_error = "startup-plan validation: " + payload
                    logging.warning("%s", last_error)

            floor, reserve, above = memory_watermarks(meminfo, cfg)
            # Budget uses this service's measured locks. Global Mlocked can
            # include unrelated audio/VM applications and must not drive growth.
            budget = max(0, owned_locked + meminfo["MemAvailable"] - reserve)
            budget = min(budget, int(meminfo["MemTotal"] * 0.9))
            configured_max = parse_size(cfg.get("max_selection_budget_bytes"))
            if configured_max is not None:
                budget = min(budget, configured_max)
            if not pause and records and now - last_reconcile >= 1 and (
                    plan_changed or abs(budget - last_budget) >= 128 * MIB
                    or any(deadline <= now for deadline in failed_until.values())):
                failed_until = {key: deadline for key, deadline in failed_until.items() if deadline > now}
                desired = choose_candidates(records, budget, cfg)
                desired_keys = {record_key(rec) for rec in desired}
                desired_priorities = {record_key(rec): rec.priority for rec in desired}
                for worker in list(workers):
                    if all(record_key(rec) in desired_keys for rec in worker.records):
                        worker.priority = min(desired_priorities[record_key(rec)] for rec in worker.records)
                        continue
                    # During the first streamed plan, keep existing workers
                    # while later records are still arriving.
                    if not validated and incoming is not None:
                        continue
                    workers.remove(worker)
                    signal_worker(worker)
                    retired.append((now, worker))
                present = {record_key(rec) for worker in workers for rec in worker.records}
                missing = [rec for rec in desired if record_key(rec) not in present
                           and record_key(rec) not in failed_until]
                pending_chunks = deque(worker_chunks(missing, cfg))
                last_reconcile, last_budget, plan_changed = now, budget, False

            active_loading = sum(not worker.ready.is_set() for worker in workers)
            loading_limit = max(1, min(16, int(cfg.get("warming_worker_max", 4))))
            if storage_profile == "rotational":
                loading_limit = min(loading_limit, 2)
            if io_busy:
                loading_limit = 1
            inflight_limit = min(parse_size(cfg.get("target_max_inflight_bytes", "2G")) or 2 * GIB,
                                 max(256 * MIB, meminfo["MemTotal"] // 8))
            # Never launch dozens of concurrent readers simply because the
            # desired cache grew by 8 GiB. Bounded outstanding I/O advances as
            # workers acknowledge completion, independent of target deadbands.
            launches = 0
            while pending_chunks and not pause and active_loading < loading_limit and launches < 2:
                chunk = pending_chunks[0]
                cost = sum(page_bytes(rec.size) for rec in chunk)
                free_room = max(0, meminfo["MemAvailable"] - reserve - inflight)
                if cost > free_room or (inflight > 0 and inflight + cost > inflight_limit):
                    break
                pending_chunks.popleft()
                try:
                    worker = start_cache_worker(chunk, cfg)
                    workers.append(worker)
                    if first_warm is None:
                        first_warm = now - started
                    inflight += cost
                    active_loading += 1
                    launches += 1
                    loading_peak = max(loading_peak, active_loading)
                except OSError as error:
                    failures += 1
                    last_error = str(error)
                    for rec in chunk:
                        failed_until[record_key(rec)] = now + 30
                    logging.exception("unable to start cache worker")
                    break

            if planner.poll() is not None:
                if planner_retry == 0:
                    planner_failures += 1
                    planner_retry = now + min(300, 5 * (2 ** min(planner_failures, 6)))
                    logging.warning("discovery process exited; saved cache stays active, restart in %.0fs", planner_retry - now)
                    try:
                        os.killpg(planner.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                if now >= planner_retry:
                    try:
                        os.killpg(planner.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    planner = subprocess.Popen(planner_command(), start_new_session=True)
                    planner_started = now
                    planner_retry = 0

            if now - last_status >= 1:
                planner_status = read_json(RUNTIME_PATH / "planner-status.json", {}) or {}
                discovered = planner_status.get("include_roots")
                if (isinstance(discovered, list) and discovered != roots
                        and all(isinstance(path, str) and path.startswith("/") for path in discovered)):
                    roots = discovered
                    cfg["_resolved_roots"] = roots
                    cfg.pop("_root_devices", None)
                    records = [rec for rec in records if cache_path_allowed(rec.path, cfg, roots)]
                    pending_chunks.clear()
                    reader.stop.set()
                    reader = PlanReader(cfg, roots)
                    plan_changed = True
                storage_profile = planner_status.get("storage_profile", storage_profile)
                atomic_json(RUNTIME_PATH / "pressure.json", {
                    "timestamp": time.time(), "pause_discovery": pause or io_busy,
                })
                actual = sum(worker.locked for worker in workers)
                requested = sum(worker.requested for worker in workers)
                payload = {
                    "controller_version": CONTROLLER_VERSION, "timestamp": int(time.time()),
                    "uptime_seconds": round(now - started, 2), "memory_profile": cfg.get("memory_profile", "normal"),
                    "phase": "pressure-paused" if pause and (policy.reason != "available" or now < policy.pause_until) else ("discovering" if not records else
                             ("warming" if pending_chunks or active_loading else ("degraded" if failed_until else "ready"))),
                    "target_locked_gib": bytes_to_gib(budget), "selected_files": sum(len(worker.records) for worker in workers),
                    "selected_gib": bytes_to_gib(requested), "owned_locked_gib": bytes_to_gib(actual),
                    "acknowledged_locked_gib": bytes_to_gib(sum(worker.locked for worker in workers if worker.ready.is_set())),
                    "inflight_gib": bytes_to_gib(inflight), "pending_chunks": len(pending_chunks),
                    "active_loaders": active_loading, "active_lockers": len(workers), "peak_loaders": loading_peak,
                    "worker_failures": failures, "worker_warnings": warning_count,
                    "plan_generation": plan_generation, "plan_validated_files": len(records),
                    "plan_skipped_files": plan_skipped, "first_warm_seconds": first_warm,
                    "memtotal_gib": bytes_to_gib(meminfo["MemTotal"]),
                    "memavailable_gib": bytes_to_gib(meminfo["MemAvailable"]),
                    "working_used_gib": bytes_to_gib(meminfo["MemTotal"] - meminfo["MemAvailable"]),
                    "cached_gib": bytes_to_gib(meminfo.get("Cached", 0)),
                    "mlocked_gib": bytes_to_gib(meminfo.get("Mlocked", 0)),
                    "unevictable_gib": bytes_to_gib(meminfo.get("Unevictable", 0)),
                    "reserve_gib": bytes_to_gib(reserve), "pressure_reason": policy.reason,
                    "controller_anon_mib": round(own_anon / MIB, 2), "last_error": last_error,
                    "foreground_io_limited": io_busy,
                    "planner_pid": planner.pid, "planner_failures": planner_failures,
                    "planner_status_age_seconds": round(max(0, time.time() - planner_status.get("timestamp", time.time())), 2),
                    "discovery": planner_status,
                }
                for key in ("inventory_files", "watcher_mode", "pending_fs_events", "scan_workers", "last_scan_epoch"):
                    payload[key] = planner_status.get(key, 0 if key != "watcher_mode" else "starting")
                atomic_json(STATUS_PATH, payload, mode=0o644)
                last_status = now
            if now - last_config > 5:
                last_config = now
                try:
                    text, new_cfg = load_config()
                    if text != config_text:
                        logging.info("configuration changed; restarting discovery and validating saved priorities")
                        cfg, config_text = new_cfg, text
                        roots = normalized_roots(cfg)
                        cfg["_resolved_roots"] = roots
                        storage_profile = resolve_scan_storage_profile(cfg)
                        pending_chunks.clear()
                        records = [rec for rec in records if cache_path_allowed(rec.path, cfg, roots)]
                        for worker in list(workers):
                            if not all(cache_path_allowed(rec.path, cfg, roots) for rec in worker.records):
                                workers.remove(worker)
                                signal_worker(worker)
                                retired.append((now, worker))
                        reader.stop.set()
                        reader = PlanReader(cfg, roots)
                        plan_changed = True
                        try:
                            os.killpg(planner.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        planner_retry = time.monotonic() + 1
                except (OSError, ValueError, TypeError) as error:
                    last_error = "invalid configuration; continuing last valid settings: " + str(error)
            time.sleep(0.1)
    finally:
        reader.stop.set()
        for worker in workers:
            signal_worker(worker)
            retired.append((time.monotonic(), worker))
        try:
            os.killpg(planner.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and (retired or planner.poll() is None):
            reap_workers(retired)
            time.sleep(0.05)
        try:
            os.killpg(planner.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for _, worker in retired:
            try:
                worker.proc.kill()
            except ProcessLookupError:
                pass
        lock_file.close()
    return 0


def diagnose() -> int:
    status = read_json(STATUS_PATH, {}) or {}
    if not status:
        print("No controller status is available.")
        return 1
    status["status_age_seconds"] = round(time.time() - status.get("timestamp", 0), 2)
    status["state_directory"] = str(STATE_PATH)
    status["startup_plan_exists"] = (STATE_PATH / "startup-plan.jsonl").exists()
    print(json.dumps(status, indent=2))
    return 0


def resident_pages(path: str) -> tuple[int, int]:
    """Query residency without reading file data or faulting it into memory."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mincore.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
    libc.mincore.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
    resident = total = 0
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("residency checks require a regular file")
        for offset in range(0, st.st_size, 128 * MIB):
            length = min(st.st_size - offset, 128 * MIB)
            count = (length + PAGE_SIZE - 1) // PAGE_SIZE
            address = libc.mmap(None, length, 0, 1, fd, offset)  # PROT_NONE, MAP_SHARED
            if address == ctypes.c_void_p(-1).value:
                raise OSError(ctypes.get_errno(), "mmap for residency query")
            try:
                vector = (ctypes.c_ubyte * count)()
                if libc.mincore(address, length, vector) != 0:
                    raise OSError(ctypes.get_errno(), "mincore residency query")
                resident += sum(value & 1 for value in vector)
                total += count
            finally:
                libc.munmap(address, length)
        return resident, total
    finally:
        os.close(fd)


def coverage_report(contains: str = "", limit: int = 2000) -> int:
    report = {"scope": "saved startup plan; residency includes natural Linux cache",
              "path_filter": contains, "file_limit": limit, "files_checked": 0,
              "unreadable_files": 0, "resident_pages": 0, "total_pages": 0, "missing_path_samples": []}
    try:
        with (STATE_PATH / "startup-plan.jsonl").open(encoding="utf-8") as source:
            next(source)
            for line in source:
                rec = record_from_list(json.loads(line))
                if contains and contains.lower() not in rec.path.lower():
                    continue
                try:
                    resident, total = resident_pages(rec.path)
                    report["resident_pages"] += resident
                    report["total_pages"] += total
                    if resident < total and len(report["missing_path_samples"]) < 50:
                        report["missing_path_samples"].append(rec.path)
                except (OSError, ValueError):
                    report["unreadable_files"] += 1
                report["files_checked"] += 1
                if report["files_checked"] >= limit:
                    break
    except (OSError, ValueError, StopIteration) as error:
        print(json.dumps({"error": str(error)}))
        return 1
    total = report["total_pages"]
    report["resident_percent"] = round(100 * report["resident_pages"] / total, 2) if total else None
    print(json.dumps(report, indent=2))
    return 0


def seed_existing_cache() -> int:
    """Carry useful existing locks into the first persistent startup plan.

    This is an install-time metadata import, not ongoing self-observation.
    It only examines direct vmtouch children of the existing systemd service.
    """
    if (STATE_PATH / "startup-plan.jsonl").exists():
        return 0
    try:
        result = subprocess.run(["systemctl", "show", "ramcache-controller.service", "--property=MainPID", "--value"],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, text=True)
        parent = int(result.stdout.strip() or "0")
        if parent <= 1:
            return 0
        children = Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
        _, cfg = load_config()
        roots = normalized_roots(cfg)
        db = InventoryDB(STATE_PATH / "inventory.sqlite3")
        seen = set()
        batch = []
        try:
            for child in children[:2048]:
                if not child.isdigit():
                    continue
                base = Path("/proc") / child
                try:
                    if (base / "comm").read_text().strip() != "vmtouch":
                        continue
                    with (base / "maps").open(encoding="utf-8", errors="surrogateescape") as mappings:
                        for line in mappings:
                            fields = line.split(None, 5)
                            if len(fields) != 6 or not fields[5].startswith("/"):
                                continue
                            path = fields[5].rstrip("\n")
                            try:
                                path = os.readlink(base / "map_files" / fields[0])
                            except OSError:
                                path = UsageObserver.unescape_mount(path)
                            if path.endswith(" (deleted)") or not cache_path_allowed(path, cfg, roots):
                                continue
                            rec = stat_record(path)
                            if not rec or (rec.dev, rec.ino) in seen:
                                continue
                            seen.add((rec.dev, rec.ino))
                            batch.append((rec, 0, 0))
                            if len(batch) >= 256:
                                db.store(classify_batch(batch), 0)
                                batch = []
                except OSError:
                    continue
            if batch:
                db.store(classify_batch(batch), 0)
            db.connection.commit()
            if db.count():
                info = db.publish(cfg, roots, reason="upgrade-import")
                db.connection.commit()
                print(f"Saved {info['plan_files']} startup files from the previous running cache.")
        finally:
            db.connection.close()
    except (OSError, ValueError, sqlite3.DatabaseError, subprocess.TimeoutExpired) as error:
        print(f"Existing-cache metadata import skipped: {error}")
    return 0


def entrypoint() -> int:
    global CONFIG_PATH, STATE_PATH, RUNTIME_PATH, STATUS_PATH, WATCH_LIST_PATH
    parser = argparse.ArgumentParser(description="Adaptive persistent Linux page-cache controller")
    parser.add_argument("--planner", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--seed-existing", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--coverage", action="store_true", help="query saved-plan page residency without loading file data")
    parser.add_argument("--path-contains", default="", help="optional filename substring for --coverage")
    parser.add_argument("--limit", type=int, default=2000, help="maximum files queried by --coverage")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--state-dir", type=Path, default=STATE_PATH)
    parser.add_argument("--runtime-dir", type=Path, default=RUNTIME_PATH)
    args = parser.parse_args()
    CONFIG_PATH, STATE_PATH, RUNTIME_PATH = args.config, args.state_dir, args.runtime_dir
    STATUS_PATH = RUNTIME_PATH / "status.json"
    WATCH_LIST_PATH = RUNTIME_PATH / "watch-list.txt"
    if args.diagnose:
        return diagnose()
    if args.coverage:
        return coverage_report(args.path_contains, max(1, args.limit))
    if args.seed_existing:
        return seed_existing_cache()
    if args.check_config:
        _, cfg = load_config()
        print(json.dumps(cfg, indent=2))
        return 0
    return run_planner() if args.planner else run_supervisor()


if __name__ == "__main__":
    raise SystemExit(entrypoint())
PY
  if ! "$PYTHON_BIN" -m py_compile "$staged_controller"; then
    rm -f "$staged_controller"
    return 1
  fi
  chmod 755 "$staged_controller"
}

write_config() {
  install -d -m 755 /etc/ramcache-controller
  "$PYTHON_BIN" - "$STAGED_CONTROLLER" <<'PYCONFIG'
import json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path
path = Path('/etc/ramcache-controller/config.json')
defaults = json.loads(r'''{"include_paths":["/","/home"],"exclude_prefixes":["/proc","/sys","/dev","/run","/tmp","/var/tmp","/var/cache/apt/archives","/var/lib/systemd/coredump","/lost+found","/swapfile"],"stay_on_filesystem":true,"auto_include_common_app_paths":true,"cross_filesystem_include_roots":["/snap"],"check_interval_seconds":1,"incremental_rescan_interval_seconds":30,"full_rescan_interval_seconds":86400,"prefer_fanotify_filesystem_watch":true,"watch_attribute_events":false,"max_pending_fs_events":350000,"scan_worker_max":12,"scan_io_worker_multiplier_nonrotational":6.0,"scan_io_worker_multiplier_mixed":2,"scan_io_worker_multiplier_unknown":3.0,"scan_rotational_worker_max":4,"scan_cooldown_every":0,"scan_cooldown_seconds":0.0,"select_cooldown_every":0,"select_cooldown_seconds":0.0,"selection_small_update_threshold":32,"memory_monitor_interval_seconds":0.5,"fast_memory_growth_window_seconds":10,"fast_memory_growth_threshold_bytes":"1G","fast_memory_growth_min_unacked_bytes":"512M","rapid_memory_window_seconds":60,"rapid_memory_growth_threshold_bytes":"2G","rapid_memory_release_multiplier":1.0,"rapid_memory_release_margin_bytes":"512M","rapid_memory_prediction_seconds":5,"rapid_memory_max_release_bytes":"6G","memory_pressure_regrow_cooldown_seconds":10,"psi_memory_some_stall_threshold_us":100000,"psi_memory_full_stall_threshold_us":20000,"psi_memory_release_bytes":"2G","memory_pressure_abort_check_every":64,"target_available_bytes":"2G","target_shrink_to_available_bytes":"3G","target_grow_above_available_bytes":"4G","target_grow_to_available_bytes":"3G","target_initial_max_bytes":"8G","target_max_grow_step_bytes":"8G","target_max_inflight_bytes":"4G","vmtouch_chunk_target_bytes":"256M","vmtouch_chunk_max_paths":8192,"max_selection_budget_total_ratio":4.0,"steam_htmlcache_budget_bytes":"1G","steam_htmlcache_max_files":65536,"firefox_webcache_budget_bytes":"4G","firefox_webcache_max_files":131072,"chromium_webcache_budget_bytes":"4G","chromium_webcache_max_files":131072,"electron_webcache_budget_bytes":"2G","electron_webcache_max_files":65536,"desktop_shader_cache_budget_bytes":"1G","desktop_shader_cache_max_files":32768,"desktop_compiled_cache_budget_bytes":"256M","desktop_compiled_cache_max_files":32768,"app_catalog_budget_bytes":"256M","app_catalog_max_files":16384,"hytale_world_budget_bytes":"2G","vrchat_content_cache_budget_bytes":"2G","target_relock_min_delta":"1G","target_relock_min_delta_ratio":0.07,"fd_limit_reserve":65536,"fd_limit_auto_max":8388608,"memlock_limit_reserve":"1G","memlock_limit_min":"1G","vmtouch_max_file_size":"128G","vmtouch_feed_pause_seconds":0.002,"vmtouch_feed_target_extra_seconds":1,"vmtouch_start_stagger_seconds":0.05,"vmtouch_stop_stagger_seconds":0.02,"low_ram_profile_enabled":true,"low_ram_total_threshold_bytes":"20G","low_ram_profile_overrides":{},"config_version":2,"adaptive_memory_reserve":true,"learning_enabled":true,"learn_file_opens":true,"process_learning_interval_seconds":2,"learning_pending_max":32768,"classification_worker_max":4,"metadata_worker_cap":12,"warming_worker_max":4,"worker_progress_timeout_seconds":120,"worker_retry_seconds":30,"learning_max_files":250000}''')
legacy = json.loads(r'''{"include_paths":["/","/home"],"exclude_prefixes":["/proc","/sys","/dev","/run","/tmp","/var/tmp","/var/cache/apt/archives","/var/lib/systemd/coredump","/lost+found","/swapfile"],"stay_on_filesystem":true,"auto_include_common_app_paths":true,"cross_filesystem_include_roots":["/snap"],"check_interval_seconds":10,"incremental_rescan_interval_seconds":300,"full_rescan_interval_seconds":86400,"prefer_fanotify_filesystem_watch":true,"watch_attribute_events":false,"max_pending_fs_events":350000,"scan_worker_max":96,"scan_io_worker_multiplier_nonrotational":6.0,"scan_io_worker_multiplier_mixed":2,"scan_io_worker_multiplier_unknown":3.0,"scan_rotational_worker_max":4,"scan_cooldown_every":0,"scan_cooldown_seconds":0.0,"select_cooldown_every":0,"select_cooldown_seconds":0.0,"selection_small_update_threshold":32,"memory_monitor_interval_seconds":0.5,"fast_memory_growth_window_seconds":10,"fast_memory_growth_threshold_bytes":"1G","fast_memory_growth_min_unacked_bytes":"512M","rapid_memory_window_seconds":60,"rapid_memory_growth_threshold_bytes":"2G","rapid_memory_release_multiplier":1.0,"rapid_memory_release_margin_bytes":"512M","rapid_memory_prediction_seconds":5,"rapid_memory_max_release_bytes":"6G","memory_pressure_regrow_cooldown_seconds":30,"psi_memory_some_stall_threshold_us":100000,"psi_memory_full_stall_threshold_us":20000,"psi_memory_release_bytes":"2G","memory_pressure_abort_check_every":64,"target_available_bytes":"4G","target_shrink_to_available_bytes":"6G","target_grow_above_available_bytes":"7G","target_grow_to_available_bytes":"6G","target_initial_max_bytes":"8G","target_max_grow_step_bytes":"8G","target_max_inflight_bytes":"8G","vmtouch_chunk_target_bytes":"1024M","vmtouch_chunk_max_paths":8192,"max_selection_budget_total_ratio":4.0,"steam_htmlcache_budget_bytes":"1G","steam_htmlcache_max_files":65536,"firefox_webcache_budget_bytes":"4G","firefox_webcache_max_files":131072,"chromium_webcache_budget_bytes":"4G","chromium_webcache_max_files":131072,"electron_webcache_budget_bytes":"2G","electron_webcache_max_files":65536,"desktop_shader_cache_budget_bytes":"1G","desktop_shader_cache_max_files":32768,"desktop_compiled_cache_budget_bytes":"256M","desktop_compiled_cache_max_files":32768,"app_catalog_budget_bytes":"256M","app_catalog_max_files":16384,"hytale_world_budget_bytes":"2G","vrchat_content_cache_budget_bytes":"2G","target_relock_min_delta":"1G","target_relock_min_delta_ratio":0.07,"fd_limit_reserve":65536,"fd_limit_auto_max":8388608,"memlock_limit_reserve":"1G","memlock_limit_min":"1G","vmtouch_max_file_size":"128G","vmtouch_feed_pause_seconds":0.002,"vmtouch_feed_target_extra_seconds":1,"vmtouch_start_stagger_seconds":0.05,"vmtouch_stop_stagger_seconds":0.02,"low_ram_profile_enabled":true,"low_ram_total_threshold_bytes":"20G","low_ram_profile_overrides":{}}''')
current = {}
if path.exists():
    current = json.loads(path.read_text())
    if not isinstance(current, dict):
        raise SystemExit('Existing RAMCache configuration must be a JSON object; it was left unchanged.')
merged = dict(defaults)
merged.update(current)
if int(current.get('config_version', 1)) < 2:
    for key, value in defaults.items():
        if key in legacy and current.get(key) == legacy[key]:
            merged[key] = value
merged['config_version'] = 2
if current == merged:
    subprocess.run([sys.executable, sys.argv[1], '--config', str(path), '--check-config'], check=True, stdout=subprocess.DEVNULL)
    print('Existing configuration preserved.')
else:
    fd, staged = tempfile.mkstemp(prefix='.config.', dir=path.parent)
    try:
        os.fchmod(fd, (path.stat().st_mode & 0o777) if path.exists() else 0o644)
        with os.fdopen(fd, 'w') as output:
            json.dump(merged, output, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        subprocess.run([sys.executable, sys.argv[1], '--config', staged, '--check-config'], check=True, stdout=subprocess.DEVNULL)
        if path.exists():
            backup = path.with_name('config.json.pre-1.4.0.' + str(time.time_ns()))
            shutil.copy2(path, backup)
            print('Previous configuration saved to', backup)
        os.replace(staged, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(staged):
            os.unlink(staged)
PYCONFIG
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

  cpu_quota="$(cpu_quota_for_thread_ratio 0.50)"
  cpu_affinity="$(cpu_affinity_for_thread_ratio 1.00)"

  cat > /etc/systemd/system/ramcache-controller.service <<UNIT
[Unit]
Description=Persistent adaptive RAM cache controller
After=local-fs.target
Wants=local-fs.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$PYTHON_BIN /opt/ramcache-controller/ramcache_controller.py
Restart=always
RestartSec=5
KillMode=control-group

# All eligible CPUs are available; total background compute is capped at half
# the machine. Bounded I/O and classification pools adapt to available CPUs.
CPUAccounting=true
CPUAffinity=$cpu_affinity
CPUQuota=$cpu_quota
CPUQuotaPeriodSec=20ms

# Foreground/user work wins scheduling and I/O contention.
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=6
CPUWeight=20
IOWeight=20
IOAccounting=true

LimitNOFILE=infinity
LimitMEMLOCK=infinity
RuntimeDirectory=ramcache-controller
RuntimeDirectoryMode=0755
StateDirectory=ramcache-controller
StateDirectoryMode=0700
TimeoutStopSec=10

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
    echo 'vm.vfs_cache_pressure=100'
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
  if command -v sysctl >/dev/null 2>&1; then
    sysctl -p /etc/sysctl.d/99-ramcache-inotify.conf >/dev/null || echo "Note: inotify limits could not be raised; reconciliation remains available."
    sysctl -p /etc/sysctl.d/99-ramcache-vm.conf >/dev/null || echo "Note: kernel VM settings could not be applied."
  fi
}

install_packages() {
  if (($# == 0)); then return 0; fi
  echo "Installing required packages: $*"
  if command -v apt-get >/dev/null 2>&1; then
    if [[ "${RAMCACHE_APT_UPDATED:-0}" != 1 ]]; then
      apt-get update || return
      RAMCACHE_APT_UPDATED=1
    fi
    apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm "$@"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "$@"
  else
    echo "ERROR: Install these dependencies with your package manager: $*" >&2
    return 1
  fi
}

build_bundled_vmtouch() {
  local staged_source staged_binary compiler
  install -d -m 755 /opt/ramcache-controller
  staged_source=$(mktemp /opt/ramcache-controller/.vmtouch-source.XXXXXX)
  staged_binary=$(mktemp /opt/ramcache-controller/.vmtouch-binary.XXXXXX)
  # Upstream: https://github.com/hoytech/vmtouch
  # Source SHA256: d954cd828bcbb75d543605a839d671376c6415747788ce9513bbf2618f2a950f
  cat > "$staged_source" <<'RAMCACHE_VMTOUCH_SOURCE'
/***********************************************************************
vmtouch - the Virtual Memory Toucher

Portable file system cache diagnostics and control

by Doug Hoyte (doug@hcsw.org)

Compilation:
  gcc -Wall -O3 -o vmtouch vmtouch.c

************************************************************************

Copyright 2009-2023 Doug Hoyte and contributors

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

***********************************************************************/


#define VMTOUCH_VERSION "1.3.1"
#define RESIDENCY_CHART_WIDTH 60
#define CHART_UPDATE_INTERVAL 0.1
#define MAX_CRAWL_DEPTH 1024
#define MAX_NUMBER_OF_IGNORES 1024
#define MAX_NUMBER_OF_FILENAME_FILTERS 1024
#define MAX_FILENAME_LENGTH 1024

#if defined(__linux__) || (defined(__hpux) && !defined(__LP64__))
// Make sure off_t is 64 bits on linux and when creating 32bit programs
// on HP-UX.
#define _FILE_OFFSET_BITS 64
#endif

#ifdef __linux__
// Required for posix_fadvise() on some linux systems
#define _XOPEN_SOURCE 600
// Required for mincore() on some linux systems
#define _DEFAULT_SOURCE
#define _BSD_SOURCE
// for O_NOATIME
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <limits.h>
#include <inttypes.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <search.h>
#include <libgen.h>
#include <fnmatch.h>

#if defined(__linux__)
// Used to find size of block devices
#include <sys/ioctl.h>
#include <sys/mount.h>
// Used to check kernal version to know if mincore reports correctly
#include <sys/utsname.h>
#endif

/*
 * To find out if the stat results from a single file correspond to a file we
 * have already seen, we need to compare both the device and the inode
 */
struct dev_and_inode
{
    dev_t dev;
    ino_t ino;
};

long pagesize;

int64_t total_pages=0;
int64_t total_pages_in_core=0;
int64_t total_files=0;
int64_t total_dirs=0;

int64_t offset=0;
int64_t max_len=0;

unsigned int junk_counter; // just to prevent any compiler optimizations

int curr_crawl_depth=0;
ino_t crawl_inodes[MAX_CRAWL_DEPTH];

// remember all inodes (for files with inode count > 1) to find duplicates
void *seen_inodes = NULL;
dev_t orig_device = 0;
int orig_device_inited = 0;


int o_touch=0;
int o_evict=0;
int o_quiet=0;
int o_verbose=0;
int o_lock=0;
int o_lockall=0;
int o_daemon=0;
int o_followsymlinks=0;
int o_singlefilesystem=0;
int o_ignorehardlinkeduplictes=0;
size_t o_max_file_size=SIZE_MAX;
int o_wait=0;
static char *o_batch = NULL;
static char *o_pidfile = NULL;
static char *o_output = NULL;
int o_0_delim = 0;


char *ignore_list[MAX_NUMBER_OF_IGNORES];
char *filename_filter_list[MAX_NUMBER_OF_FILENAME_FILTERS];
int number_of_ignores=0;
int number_of_filename_filters=0;


int exit_pipe[2];

int daemon_pid;


void send_exit_signal(char code) {
  if (daemon_pid == 0 && o_wait) {
    if (write(exit_pipe[1], &code, 1) < 0)
      fprintf(stderr, "vmtouch: FATAL: write: %s", strerror(errno));
  }
}

void usage() {
  printf("\n");
  printf("vmtouch v%s - the Virtual Memory Toucher by Doug Hoyte\n", VMTOUCH_VERSION);
  printf("Portable file system cache diagnostics and control\n\n");
  printf("Usage: vmtouch [OPTIONS] ... FILES OR DIRECTORIES ...\n\nOptions:\n");
  printf("  -t touch pages into memory\n");
  printf("  -e evict pages from memory\n");
  printf("  -l lock pages in physical memory with mlock(2)\n");
  printf("  -L lock pages in physical memory with mlockall(2)\n");
  printf("  -d daemon mode\n");
  printf("  -m <size> max file size to touch\n");
  printf("  -p <range> use the specified portion instead of the entire file\n");
  printf("  -f follow symbolic links\n");
  printf("  -F don't crawl different filesystems\n");
  printf("  -h also count hardlinked copies\n");
  printf("  -i <pattern> ignores files and directories that match this pattern\n");
  printf("  -I <pattern> only process files that match this pattern\n");
  printf("  -b <list file> get files or directories from the list file\n");
  printf("  -0 in batch mode (-b) separate paths with NUL byte instead of newline\n");
  printf("  -w wait until all pages are locked (only useful together with -d)\n");
  printf("  -P <pidfile> write a pidfile (only useful together with -l or -L)\n");
  printf("  -o <type> output in machine friendly format.  'kv' for key=value pairs.\n");
  printf("  -v verbose\n");
  printf("  -q quiet\n");
  exit(1);
}

static void fatal(const char *fmt, ...) {
  va_list ap;
  char buf[4096];

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  fprintf(stderr, "vmtouch: FATAL: %s\n", buf);
  send_exit_signal(1);
  exit(1);
}

static void warning(const char *fmt, ...) {
  va_list ap;
  char buf[4096];

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if (!o_quiet) fprintf(stderr, "vmtouch: WARNING: %s\n", buf);
}

static void reopen_all() {
  if (freopen("/dev/null", "r", stdin) == NULL ||
      freopen("/dev/null", "w", stdout) == NULL ||
      freopen("/dev/null", "w", stdout) == NULL)
    fatal("freopen: %s", strerror(errno));
}

static int wait_for_child() {
  int exit_read = 0;
  char exit_value = 0;
  int wait_status;

  while (1) {
    struct timeval tv;
    fd_set rfds;
    FD_ZERO(&rfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_SET(exit_pipe[0], &rfds);
    if (select(exit_pipe[0] + 1, &rfds, NULL, NULL, &tv) < 0)
      fatal("select: %s", strerror(errno));

    if (waitpid(daemon_pid, &wait_status, WNOHANG) > 0)
      fatal("daemon shut down unexpectedly");

    if (FD_ISSET(exit_pipe[0], &rfds))
      break;
  }
  exit_read = read(exit_pipe[0], &exit_value, 1);
  if (exit_read < 0)
    fatal("read: %s", strerror(errno));
  return exit_value;
}

void go_daemon() {
  daemon_pid = fork();
  if (daemon_pid == -1)
    fatal("fork: %s", strerror(errno));
  if (daemon_pid) {
    if (o_wait)
      exit(wait_for_child());
    exit(0);
  }

  if (setsid() == -1)
    fatal("setsid: %s", strerror(errno));

  if (!o_wait) reopen_all();
}


char *pretty_print_size(int64_t inp) {
  static char output[100];

  if (inp<1024) {
    snprintf(output, sizeof(output), "%" PRId64, inp);
    return output;
  }
  inp /= 1024;
  if (inp<1024) {
    snprintf(output, sizeof(output), "%" PRId64 "K", inp);
    return output;
  }
  inp /= 1024;
  if (inp<1024) {
    snprintf(output, sizeof(output), "%" PRId64 "M", inp);
    return output;
  }
  inp /= 1024;
  snprintf(output, sizeof(output), "%" PRId64 "G", inp);
  return output;
}

/*
 *  Convert ASCII string to int64_t number
 *  Note: The inp parameter can't be a character constant
 *        because it will be overwritten.
 */
int64_t parse_size(char *inp) {
  char *tp;
  int len=strlen(inp);
  char *errstr = "bad size. examples: 4096, 4k, 100M, 1.5G";
  char mult_char;
  int mult=1;
  double val;

  if (len < 1) fatal(errstr);

  mult_char = tolower(inp[len-1]);

  if (isalpha(mult_char)) {
    switch(mult_char) {
      case 'k': mult = 1024; break;
      case 'm': mult = 1024*1024; break;
      case 'g': mult = 1024*1024*1024; break;
      default: fatal("unknown size multiplier: %c", mult_char);
    }
    inp[len-1] = '\0';
  }

  val = strtod(inp, &tp);

  if (val < 0 || val == HUGE_VAL || *tp != '\0') fatal(errstr);

  val *= mult;

  if (val > INT64_MAX) fatal(errstr);

  return (int64_t) val;
}

int64_t bytes2pages(int64_t bytes) {
  return (bytes+pagesize-1) / pagesize;
}

void parse_range(char *inp) {
  char *token;
  int64_t upper_range=0;
  int64_t lower_range=0;

  token = strsep(&inp,"-");

  if (inp == NULL)
    upper_range = parse_size(token); // single value provided
  else {
    if (*token != '\0')
      lower_range = parse_size(token); // value before hyphen

    token = strsep(&inp,"-");
    if (*token != '\0')
      upper_range = parse_size(token); // value after hyphen

    if ((token = strsep(&inp,"-")) != NULL) fatal("malformed range: multiple hyphens");
  }

  // offset must be multiple of pagesize
  offset = (lower_range / pagesize) * pagesize;

  if (upper_range) {
    if (upper_range <= offset) fatal("range limits out of order");

    max_len = upper_range - offset;
  }
}


void parse_ignore_item(char *inp) {
  if (inp == NULL) {
    return;
  }

  if (strlen(inp) > MAX_FILENAME_LENGTH) {
    fatal("too long pattern provided to -i: %s", inp);
    return;
  }

  if (number_of_ignores >= MAX_NUMBER_OF_IGNORES) {
    fatal("too many patterns passed to -i. Max is %d", MAX_NUMBER_OF_IGNORES);
    return;
  }

  ignore_list[number_of_ignores] = strdup(inp);
  number_of_ignores++;
}

void parse_filename_filter_item(char *inp) {
  if (inp == NULL) {
    return;
  }

  if (strlen(inp) > MAX_FILENAME_LENGTH) {
    fatal("too long pattern provided to -I: %s", inp);
    return;
  }

  if (number_of_filename_filters >= MAX_NUMBER_OF_FILENAME_FILTERS) {
    fatal("too many patterns passed to -I. Max is %d", MAX_NUMBER_OF_FILENAME_FILTERS);
    return;
  }

  filename_filter_list[number_of_filename_filters] = strdup(inp);
  number_of_filename_filters++;
}


int aligned_p(void *p) {
  return 0 == ((long)p & (pagesize-1));
}

int is_mincore_page_resident(char p) {
  return p & 0x1;
}


void increment_nofile_rlimit() {
  struct rlimit r;

  if (getrlimit(RLIMIT_NOFILE, &r))
    fatal("increment_nofile_rlimit: getrlimit (%s)", strerror(errno));

  r.rlim_cur = r.rlim_max + 1;
  r.rlim_max = r.rlim_max + 1;

  if (setrlimit(RLIMIT_NOFILE, &r)) {
    if (errno == EPERM) {
      if (getuid() == 0 || geteuid() == 0) fatal("system open file limit reached");
      fatal("open file limit reached and unable to increase limit. retry as root");
    }
    fatal("increment_nofile_rlimit: setrlimit (%s)", strerror(errno));
  }
}



double gettimeofday_as_double() {
  struct timeval tv;
  gettimeofday(&tv, NULL);

  return tv.tv_sec + (tv.tv_usec/1000000.0);
}



void print_page_residency_chart(FILE *out, char *mincore_array, int64_t pages_in_file) {
  int64_t pages_in_core=0;
  int64_t pages_per_char;
  int64_t i,j=0,curr=0;

  if (pages_in_file <= RESIDENCY_CHART_WIDTH) pages_per_char = 1;
  else pages_per_char = (pages_in_file / RESIDENCY_CHART_WIDTH) + 1;

  fprintf(out, "\r[");

  for (i=0; i<pages_in_file; i++) {
    if (is_mincore_page_resident(mincore_array[i])) {
      curr++;
      pages_in_core++;
    }
    j++;
    if (j == pages_per_char) {
      if (curr == pages_per_char) fprintf(out, "O");
      else if (curr == 0) fprintf(out, " ");
      else fprintf(out, "o");

      j = curr = 0;
    }
  }

  if (j) {
    if (curr == j) fprintf(out, "O");
    else if (curr == 0) fprintf(out, " ");
    else fprintf(out, "o");
  }

  fprintf(out, "] %" PRId64 "/%" PRId64, pages_in_core, pages_in_file);

  fflush(out);
}


#ifdef __linux__
// check if mincore will report correctly, due side-channel vulnerabilities
// from 5.2+ it only reports if process has write permission to the file
// https://lwn.net/Articles/778437/
static int can_do_mincore(struct stat *st) {

  struct utsname utsinfo;
  if (uname(&utsinfo) == 0) {
    unsigned long ver[16];
    int i=0;
    char *p = utsinfo.release;
    while (*p) {
      if (isdigit(*p)) {
          ver[i] = strtol(p, &p, 10);
          i++;
      } else {
          p++;
      }
    }
    // kernal < 5.2
    if (ver[0]<5||ver[1]<2)
      return 1;
  }

  uid_t uid = getuid();
  return st->st_uid == uid ||
         (st->st_gid == getgid() && (st->st_mode&S_IWGRP)) ||
         (st->st_mode&S_IWOTH) ||
         uid == 0;
}
#endif


void vmtouch_file(char *path) {
  int fd = -1;
  void *mem = NULL;
  struct stat sb;
  int64_t len_of_file=0;
  int64_t len_of_range=0;
  int64_t pages_in_range;
  int i;
  int res;
  int open_flags;

  retry_open:

  open_flags = O_RDONLY;

#if defined(O_NOATIME)
  open_flags |= O_NOATIME;
#endif

  fd = open(path, open_flags, 0);

#if defined(O_NOATIME)
  if (fd == -1 && errno == EPERM) {
    open_flags &= ~O_NOATIME;
    fd = open(path, open_flags, 0);
  }
#endif

  if (fd == -1) {
    if (errno == ENFILE || errno == EMFILE) {
      increment_nofile_rlimit();
      goto retry_open;
    }

    warning("unable to open %s (%s), skipping", path, strerror(errno));
    goto bail;
  }

  res = fstat(fd, &sb);

  if (res) {
    warning("unable to fstat %s (%s), skipping", path, strerror(errno));
    goto bail;
  }

  if (S_ISBLK(sb.st_mode)) {
#if defined(__linux__)
    if (ioctl(fd, BLKGETSIZE64, &len_of_file)) {
      warning("unable to ioctl %s (%s), skipping", path, strerror(errno));
      goto bail;
    }
#else
    fatal("discovering size of block devices not (yet?) supported on this platform");
#endif
  } else {
    len_of_file = sb.st_size;
  }


  if (len_of_file == 0) {
    goto bail;
  }

  if (len_of_file > o_max_file_size) {
    warning("file %s too large, skipping", path);
    goto bail;
  }


  if (max_len > 0 && (offset + max_len) < len_of_file) {
    len_of_range = max_len;
  } else if (offset >= len_of_file) {
    warning("file %s smaller than offset, skipping", path);
    goto bail;
  } else {
    len_of_range = len_of_file - offset;
  }

  mem = mmap(NULL, len_of_range, PROT_READ, MAP_SHARED, fd, offset);

  if (mem == MAP_FAILED) {
    warning("unable to mmap file %s (%s), skipping", path, strerror(errno));
    goto bail;
  }

  if (!aligned_p(mem)) fatal("mmap(%s) wasn't page aligned", path);

  pages_in_range = bytes2pages(len_of_range);

  total_pages += pages_in_range;

  if (o_evict) {
    if (o_verbose) printf("Evicting %s\n", path);

#if defined(__linux__) || defined(__hpux)
    if (posix_fadvise(fd, offset, len_of_range, POSIX_FADV_DONTNEED))
      warning("unable to posix_fadvise file %s (%s)", path, strerror(errno));
#elif defined(__FreeBSD__) || defined(__sun__) || defined(__APPLE__)
    if (msync(mem, len_of_range, MS_INVALIDATE))
      warning("unable to msync invalidate file %s (%s)", path, strerror(errno));
#else
    fatal("cache eviction not (yet?) supported on this platform");
#endif
  } else {
    double last_chart_print_time=0.0, temp_time;
    char *mincore_array = malloc(pages_in_range);
    if (mincore_array == NULL) fatal("Failed to allocate memory for mincore array (%s)", strerror(errno));

    // 3rd arg to mincore is char* on BSD and unsigned char* on linux
    if (mincore(mem, len_of_range, (void*)mincore_array)) fatal("mincore %s (%s)", path, strerror(errno));
    for (i=0; i<pages_in_range; i++) {
      if (is_mincore_page_resident(mincore_array[i])) {
        total_pages_in_core++;
      }
    }

    if (o_verbose) {
      printf("%s\n", path);
#ifdef __linux__
      if (!can_do_mincore(&sb)) {
        warning("Process does not have write permission, residency chart will not be accurate");
      }
#endif
      last_chart_print_time = gettimeofday_as_double();
      print_page_residency_chart(stdout, mincore_array, pages_in_range);
    }

    if (o_touch) {
      for (i=0; i<pages_in_range; i++) {
        junk_counter += ((char*)mem)[i*pagesize];
        mincore_array[i] = 1;

        if (o_verbose) {
          temp_time = gettimeofday_as_double();

          if (temp_time > (last_chart_print_time+CHART_UPDATE_INTERVAL)) {
            last_chart_print_time = temp_time;
            print_page_residency_chart(stdout, mincore_array, pages_in_range);
          }
        }
      }
    }

    if (o_verbose) {
      print_page_residency_chart(stdout, mincore_array, pages_in_range);
      printf("\n");
    }

    free(mincore_array);
  }

  if (o_lock) {
    if (mlock(mem, len_of_range))
      fatal("mlock: %s (%s)", path, strerror(errno));
  }

  bail:

  if (!o_lock && !o_lockall && mem) {
    if (munmap(mem, len_of_range)) warning("unable to munmap file %s (%s)", path, strerror(errno));
  }

  if (fd != -1) {
    close(fd);
  }
}


// compare device and inode information
int compare_func(const void *p1, const void *p2)
{
  const struct dev_and_inode *kp1 = p1, *kp2 = p2;
  int cmp1;
  cmp1 = (kp1->ino > kp2->ino) - (kp1->ino < kp2->ino);
  if (cmp1 != 0)
    return cmp1;
  return (kp1->dev > kp2->dev) - (kp1->dev < kp2->dev);
}

// add device and inode information to the tree of known inodes
static inline void add_object (struct stat *st)
{
  struct dev_and_inode *newp = malloc (sizeof (struct dev_and_inode));
  if (newp == NULL) {
    fatal("malloc: out of memory");
  }
  newp->dev = st->st_dev;
  newp->ino = st->st_ino;
  if (tsearch(newp, &seen_inodes, compare_func) == NULL) {
    fatal("tsearch: out of memory");
  }
}


int is_ignored(const char* path) {
  char *path_copy;
  int match, i;

  if (!number_of_ignores) return 0;

  path_copy = strdup(path);
  match = 0;

  char *filename = basename(path_copy);

  for (i = 0; i < number_of_ignores; i++) {
    if (fnmatch(ignore_list[i], filename, 0) == 0) {
      match = 1;
      break;
    }
  }

  free(path_copy);
  return match;
}


int is_filename_filtered(const char* path) {
  char *path_copy;
  int match, i;

  if (!number_of_filename_filters) return 1;

  path_copy = strdup(path);
  match = 0;

  char *filename = basename(path_copy);

  for (i = 0; i < number_of_filename_filters; i++) {
    if (fnmatch(filename_filter_list[i], filename, 0) == 0) {
      match = 1;
      break;
    }
  }

  free(path_copy);
  return match;
}



// return true only if the device and inode information has not been added before
static inline int find_object(struct stat *st)
{
  struct dev_and_inode obj;
  void *res;
  obj.dev = st->st_dev;
  obj.ino = st->st_ino;
  res = (void *) tfind(&obj, &seen_inodes, compare_func);
  return res != (void *) NULL;
}

void vmtouch_crawl(char *path) {
  struct stat sb;
  DIR *dirp;
  struct dirent *de;
  char npath[PATH_MAX];
  int res;
  int tp_path_len = strlen(path);
  int i;

  if (path[tp_path_len-1] == '/' && tp_path_len > 1) path[tp_path_len-1] = '\0'; // prevent ugly double slashes when printing path names

  if (is_ignored(path)) {
    return;
  }

  res = o_followsymlinks ? stat(path, &sb) : lstat(path, &sb);

  if (res) {
    warning("unable to stat %s (%s)", path, strerror(errno));
    return;
  } else {
    if (S_ISLNK(sb.st_mode)) {
      warning("not following symbolic link %s", path);
      return;
    }

    if (o_singlefilesystem) {
      if (!orig_device_inited) {
        orig_device = sb.st_dev;
        orig_device_inited = 1;
      } else {
        if (sb.st_dev != orig_device) {
          warning("not recursing into separate filesystem %s", path);
          return;
        }
      }
    }

    if (!o_ignorehardlinkeduplictes && sb.st_nlink > 1) {
      /*
       * For files with more than one link to it, ignore it if we already know
       * inode.  Without this check files copied as hardlinks (cp -al) are
       * counted twice (which may lead to a cache usage of more than 100% of
       * RAM).
       */
      if (find_object(&sb)) {
        // we already saw the device and inode referenced by this file
        return;
      } else {
        add_object(&sb);
      }
    }

    if (S_ISDIR(sb.st_mode)) {
      for (i=0; i<curr_crawl_depth; i++) {
        if (crawl_inodes[i] == sb.st_ino) {
          warning("symbolic link loop detected: %s", path);
          return;
        }
      }

      if (curr_crawl_depth == MAX_CRAWL_DEPTH)
        fatal("maximum directory crawl depth reached: %s", path);

      total_dirs++;

      crawl_inodes[curr_crawl_depth] = sb.st_ino;

      retry_opendir:

      dirp = opendir(path);

      if (dirp == NULL) {
        if (errno == ENFILE || errno == EMFILE) {
          increment_nofile_rlimit();
          goto retry_opendir;
        }

        warning("unable to opendir %s (%s), skipping", path, strerror(errno));
        return;
      }

      while((de = readdir(dirp)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        if (snprintf(npath, sizeof(npath), "%s/%s", path, de->d_name) >= sizeof(npath)) {
          warning("path too long %s", path);
          goto bail;
        }

        curr_crawl_depth++;
        vmtouch_crawl(npath);
        curr_crawl_depth--;
      }

      bail:

      if (closedir(dirp)) {
        warning("unable to closedir %s (%s)", path, strerror(errno));
        return;
      }
    } else if (S_ISLNK(sb.st_mode)) {
      warning("not following symbolic link %s", path);
      return;
    } else if (S_ISREG(sb.st_mode) || S_ISBLK(sb.st_mode)) {
      if (is_filename_filtered(path)) {
        total_files++;
        vmtouch_file(path);
      }
    } else {
      warning("skipping non-regular file: %s", path);
    }
  }
}

static void vmtouch_batch_crawl(const char *path) {
  FILE *f;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;
  int delim = o_0_delim ? '\0' : '\n';

  if (!strcmp(path, "-")) {
    f = stdin;
  } else {
    f = fopen(path, "r");
    if (!f) {
      warning("unable to open %s (%s), skipping", path, strerror(errno));
      return;
    }
  }

  while ((read = getdelim(&line, &len, delim, f)) != -1) {
    // strip the newline character
    line[read-1] = '\0';
    vmtouch_crawl(line);
  }

  free(line);
  fclose(f);
}

static void remove_pidfile() {
  int res = 0;

  res = unlink(o_pidfile);
  if (res < 0 && errno != ENOENT) {
    warning("unable to remove pidfile %s (%s)", o_pidfile, strerror(errno));
  }
}

static void write_pidfile() {
  FILE *f = NULL;
  size_t wrote = 0;

  f = fopen(o_pidfile, "w");
  if (!f) {
    warning("unable to open pidfile %s (%s), skipping", o_pidfile, strerror(errno));
    return;
  }

  wrote = fprintf(f, "%d\n", getpid());

  fclose(f);

  if (wrote < 0) {
    warning("unable to write to pidfile %s (%s), deleting it", o_pidfile, strerror(errno));
    remove_pidfile();
  }
}

static void signal_handler_clear_pidfile(int signal_num) {
  remove_pidfile();
}

static void register_signals_for_pidfile() {
  struct sigaction sa = {0};
  sa.sa_handler = signal_handler_clear_pidfile;
  if (sigaction(SIGINT, &sa, NULL) < 0 ||
      sigaction(SIGTERM, &sa, NULL) < 0 ||
      sigaction(SIGQUIT, &sa, NULL) < 0) {
    warning("unable to register signals for pidfile (%s), skipping", strerror(errno));
  }
}






int main(int argc, char **argv) {
  int ch, i;
  char *prog = argv[0];
  struct timeval start_time;
  struct timeval end_time;

  if (pipe(exit_pipe))
    fatal("pipe: %s", strerror(errno));

  pagesize = sysconf(_SC_PAGESIZE);

  while((ch = getopt(argc, argv, "tevqlLdfFh0i:I:p:b:m:P:wo:")) != -1) {
    switch(ch) {
      case '?': usage(); break;
      case 't': o_touch = 1; break;
      case 'e': o_evict = 1; break;
      case 'q': o_quiet = 1; break;
      case 'v': o_verbose++; break;
      case 'l': o_lock = 1;
                o_touch = 1; break;
      case 'L': o_lockall = 1;
                o_touch = 1; break;
      case 'd': o_daemon = 1; break;
      case 'f': o_followsymlinks = 1; break;
      case 'F': o_singlefilesystem = 1; break;
      case 'h': o_ignorehardlinkeduplictes = 1; break;
      case 'p': parse_range(optarg); break;
      case 'i': parse_ignore_item(optarg); break;
      case 'I': parse_filename_filter_item(optarg); break;
      case 'm': {
        int64_t val = parse_size(optarg);
        o_max_file_size = (size_t) val;
        if (val != (int64_t) o_max_file_size) fatal("value for -m too big to fit in a size_t");
        break;
      }
      case 'w': o_wait = 1; break;
      case 'b': o_batch = optarg; break;
      case '0': o_0_delim = 1; break;
      case 'P': o_pidfile = optarg; break;
      case 'o': o_output = optarg; break;
    }
  }

  argc -= optind;
  argv += optind;

  if (o_touch) {
    if (o_evict) fatal("invalid option combination: -t and -e");
  }

  if (o_evict) {
    if (o_lock) fatal("invalid option combination: -e and -l");
  }

  if (o_lock && o_lockall) fatal("invalid option combination: -l and -L");

  if (o_daemon) {
    if (!(o_lock || o_lockall)) fatal("daemon mode must be combined with -l or -L");
    if (!o_wait) {
      o_quiet = 1;
      o_verbose = 0;
   }
  }

  if (o_wait && !o_daemon) fatal("wait mode must be combined with -d");

  if (o_quiet && o_verbose) fatal("invalid option combination: -q and -v");

  if (o_pidfile && (!o_lock && !o_lockall)) fatal("pidfile can only be created when -l or -L is specified");

  if (!argc && !o_batch) {
    printf("%s: no files or directories specified\n", prog);
    usage();
  }

  // Must be done now because mlock() not inherited across fork()
  if (o_daemon) go_daemon();

  gettimeofday(&start_time, NULL);

  if (o_batch) {
      vmtouch_batch_crawl(o_batch);
  }

  for (i=0; i<argc; i++) vmtouch_crawl(argv[i]);

  gettimeofday(&end_time, NULL);

  int64_t total_pages_in_core_size = total_pages_in_core * pagesize;
  int64_t total_pages_size         = total_pages * pagesize;
  double  total_pages_in_core_perc = 100.0*total_pages_in_core/total_pages;
  double  elapsed                  = (end_time.tv_sec - start_time.tv_sec) + (double)(end_time.tv_usec - start_time.tv_usec)/1000000.0;

  if (o_lock || o_lockall) {
    if (o_lockall) {
      if (mlockall(MCL_CURRENT))
        fatal("unable to mlockall (%s)", strerror(errno));
    }

    if (o_pidfile) {
      register_signals_for_pidfile();
      write_pidfile();
    }

    if (!o_quiet) printf("LOCKED %" PRId64 " pages (%s)\n", total_pages, pretty_print_size(total_pages_size));

    if (o_wait) reopen_all();

    send_exit_signal(0);
    select(0, NULL, NULL, NULL, NULL);
    exit(0);
  }

  if (!o_quiet) {
    if (o_output == NULL) {
      if (o_verbose) printf("\n");
      printf("           Files: %" PRId64 "\n", total_files);
      printf("     Directories: %" PRId64 "\n", total_dirs);
      if (o_touch)
        printf("   Touched Pages: %" PRId64 " (%s)\n", total_pages, pretty_print_size(total_pages_size));
      else if (o_evict)
        printf("   Evicted Pages: %" PRId64 " (%s)\n", total_pages, pretty_print_size(total_pages_size));
      else {
        printf("  Resident Pages: %" PRId64 "/%" PRId64 "  ", total_pages_in_core, total_pages);
        printf("%s/", pretty_print_size(total_pages_in_core_size));
        printf("%s  ", pretty_print_size(total_pages_size));
        if (total_pages)
          printf("%.3g%%", total_pages_in_core_perc);
        printf("\n");
      }
      printf("         Elapsed: %.5g seconds\n", elapsed);
    } else if (strncmp(o_output, "kv", 2) == 0) {
      char *desc = o_touch ? "Touched" :
                   o_evict ? "Evicted" :
                             "Resident";
      printf("Files=%" PRId64 " Directories=%" PRId64 " %sPages=%" PRId64 " TotalPages=%" PRId64 " %sSize=%" PRId64 " TotalSize=%" PRId64 " %sPercent=%.3g Elapsed=%.5g\n", 
        total_files, total_dirs, desc, total_pages_in_core, total_pages, desc, total_pages_in_core_size, total_pages_size, desc, total_pages_in_core_perc, elapsed);
    }
  }

  return 0;
}

RAMCACHE_VMTOUCH_SOURCE
  if [[ -x /opt/ramcache-controller/vmtouch ]] && cmp -s "$staged_source" /opt/ramcache-controller/vmtouch.c; then
    rm -f "$staged_source" "$staged_binary"
    return 0
  fi
  compiler=$(command -v cc || command -v gcc || true)
  if [[ -z "$compiler" ]] || ! "$compiler" -x c -O2 -Wall -Wextra "$staged_source" -o "$staged_binary" -lm; then
    if command -v apt-get >/dev/null 2>&1; then
      install_packages gcc libc6-dev || { rm -f "$staged_source" "$staged_binary"; return 1; }
    elif command -v pacman >/dev/null 2>&1; then
      install_packages gcc glibc || { rm -f "$staged_source" "$staged_binary"; return 1; }
    else
      install_packages gcc glibc-devel || { rm -f "$staged_source" "$staged_binary"; return 1; }
    fi
    compiler=$(command -v cc || command -v gcc || true)
    if [[ -z "$compiler" ]] || ! "$compiler" -x c -O2 -Wall -Wextra "$staged_source" -o "$staged_binary" -lm; then
      rm -f "$staged_source" "$staged_binary"
      echo "ERROR: bundled vmtouch could not be built; the running controller was left in place." >&2
      return 1
    fi
  fi
  chmod 755 "$staged_binary"
  chmod 644 "$staged_source"
  mv -f "$staged_source" /opt/ramcache-controller/vmtouch.c
  mv -f "$staged_binary" /opt/ramcache-controller/vmtouch
  echo "Built the bundled upstream vmtouch snapshot for this machine."
}

ensure_dependencies() {
  local packages=()
  command -v python3 >/dev/null 2>&1 || packages+=(python3)
  command -v inotifywait >/dev/null 2>&1 || packages+=(inotify-tools)
  command -v systemctl >/dev/null 2>&1 || {
    echo "ERROR: RAMCache requires a Linux system using systemd." >&2
    return 1
  }
  if ((${#packages[@]})); then
    install_packages "${packages[@]}"
  fi
  local candidate
  PYTHON_BIN=""
  for candidate in /usr/bin/python3 /usr/bin/python3.13 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3.10 "$(command -v python3 || true)"; do
    if [[ -x "$candidate" ]] && "$candidate" -c 'import sys, sqlite3; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      break
    fi
  done
  if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: Python 3.10 or newer with sqlite3 is required. Install it and rerun this command." >&2
    return 1
  fi
  command -v inotifywait >/dev/null 2>&1 || {
    echo "ERROR: inotify-tools could not be installed." >&2
    return 1
  }
  if ! command -v vmtouch >/dev/null 2>&1; then
    if [[ -x /opt/ramcache-controller/vmtouch ]]; then
      build_bundled_vmtouch
    elif command -v pacman >/dev/null 2>&1 && ! pacman -Si vmtouch >/dev/null 2>&1; then
      build_bundled_vmtouch
    elif ! install_packages vmtouch; then
      build_bundled_vmtouch
    fi
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
  # Native open learning is optional; changes use the installed portable tools.
  # Each capability is checked again by the running controller.
  if probe_fanotify_filesystem_watch; then
    echo "Filesystem changes: fanotify supported; recursive inotify remains the fallback."
  else
    echo "Filesystem changes: recursive inotify; periodic reconciliation also remains active."
  fi
}

install_all() {
  need_root
  export DEBIAN_FRONTEND=noninteractive
  ensure_dependencies
  ensure_fs_watch_tools
  # Stage and validate both program and settings before replacing either.
  write_controller
  if ! write_config; then
    rm -f "$STAGED_CONTROLLER"
    return 1
  fi
  mv -f "$STAGED_CONTROLLER" /opt/ramcache-controller/ramcache_controller.py
  install -d -m 700 /var/lib/ramcache-controller
  "$PYTHON_BIN" /opt/ramcache-controller/ramcache_controller.py --seed-existing
  write_service
  write_sysctls
  systemctl daemon-reload
  systemctl enable ramcache-controller.service
  systemctl restart ramcache-controller.service
  echo
  echo "Installed RAMCache v1.4.0. Existing configuration and learned state are retained on updates."
  echo "Status: sudo bash ramcache.sh diagnose"
  echo "        systemctl status ramcache-controller.service --no-pager"
  echo "        python3 -m json.tool /run/ramcache-controller/status.json"
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
  rm -rf /var/lib/ramcache-controller
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
  echo "RAM cache controller installer: v1.4.0"
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

coverage_all() {
  python3 /opt/ramcache-controller/ramcache_controller.py --coverage "$@"
}

diagnose_all() {
  local controller=/opt/ramcache-controller/ramcache_controller.py
  if [[ ! -r "$controller" ]]; then
    echo "RAMCache is not installed."
    return 1
  fi
  python3 "$controller" --diagnose
}

case "$ACTION" in
  install|update) install_all ;;
  uninstall) uninstall_all ;;
  status) status_all ;;
  diagnose) diagnose_all ;;
  coverage) coverage_all "${@:2}" ;;
  *)
    echo "Usage: $0 {install|update|uninstall|status|diagnose|coverage}"
    exit 1
    ;;
esac

