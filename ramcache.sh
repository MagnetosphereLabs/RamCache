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
import resource
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
    "/usr/lib/thunderbird",
    "/usr/lib/chromium",
    "/usr/lib/chromium-browser",
    "/opt/google/chrome",
    "/opt/brave.com",
    "/opt/microsoft/msedge",
    "/snap/firefox",
    "/snap/chromium",
)

DESKTOP_SUPPORT_PREFIXES = (
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
    "/usr/share/systemd",
    "/usr/share/polkit-1",
    "/usr/share/fonts",
    "/usr/local/share/fonts",
    "/usr/share/themes",
    "/usr/share/sounds",
    "/usr/share/thumbnailers",
    "/usr/share/wayland",
    "/usr/share/wayland-sessions",
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
    "/usr/share/cinnamon",
    "/usr/share/mate",
    "/usr/share/xfce4",
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
    "/ubuntu12_32/",
    "/ubuntu12_64/",
    "/compatibilitytools.d/",
    "/steamapps/compatdata/",
    "/steamapps/shadercache/",
    "/steamapps/common/proton",
    "/steamapps/common/steamlinuxruntime",
    "/steamapps/common/steam linux runtime",
    "/steamapps/common/steamworks shared",
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
    ".rb", ".pl", ".pm", ".class",
)

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
        or path_contains_any(path, ELECTRON_APP_SUBSTRINGS)
    )


def should_prune_dir(path: str) -> bool:
    p = os.path.normpath(path).lower()

    if path_has_prefix(p, HARD_COLD_PREFIXES):
        return True

    if is_browser_http_cache_path(p) and not is_shader_cache_path(p):
        return True

    if path_contains_any(p, PRUNE_DIR_SUBSTRINGS):
        return True

    # Do not scan arbitrary project dependency forests, but keep packaged
    # Electron app runtime node_modules because those can be part of app launch.
    if "/node_modules/" in p and "/resources/app/node_modules/" not in p:
        return True

    return False



def is_hard_cold_file(path: str, name: str, size: int) -> bool:
    if path_has_prefix(path, HARD_COLD_PREFIXES):
        return True

    if is_browser_http_cache_path(path) and not is_shader_cache_path(path):
        return True

    # These are early-priority cache targets, but they should not be
    # hard-banned. On high-RAM desktops, after OS/app/runtime/Steam/desktop
    # candidates are selected, they are valid late fallback files so the cache
    # can actually use the available RAM instead of stopping early.
    #
    # Only reject huge cold blobs that are unlikely to help launch/system
    # responsiveness and would make shrink chunks coarse.
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

    if is_hard_cold_file(path, name, size):
        return (99, 0, 0)

    executable = file_is_executable(rec)
    shared_lib = is_shared_library_name(name)
    steam = is_steam_path(path)
    vr = is_vr_path(path)
    shader = is_shader_cache_path(path)
    browser_profile = is_browser_profile_path(path)
    user_app = path_contains_any(path, USER_APP_SUBSTRINGS)
    cosmic = path_contains_any(path, COSMIC_SUBSTRINGS)

    # Tier 0: core OS/runtime foundation. Keep the proven wins:
    # dynamic linker, system shared libs, core binaries, graphics/audio libs,
    # GTK/Qt/PipeWire/ALSA/Vulkan/Mesa, etc.
    if (
        path_has_prefix(path, HOT_SYSTEM_PREFIXES)
        and (
            shared_lib
            or executable
            or name in HOT_SPECIAL_NAMES
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

    # Tier 1: Steam / Proton / Wine / game / VR launch path.
    # This must happen before generic app-runtime classification.
    if steam or vr or shader:
        if name.startswith("appmanifest_") and name.endswith(".acf"):
            return (1, 1250, 0)

        if name in STEAM_STARTUP_NAMES:
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

        # Game launch support: prefer executables, config, manifests.
        # Do not spend early RAM on giant opaque game asset packs.
        if shared_lib or executable or name.endswith((".dll", ".exe")):
            return (1, 930, 0)

        if name.endswith(CONFIG_SUFFIXES):
            return (1, 850, 0)

        if shader and name.endswith(SHADER_SUFFIXES) and size <= 256 * MIB:
            return (1, 760, 0)

        if size <= 8 * MIB:
            return (2, 520, 0)

        return (5, 120, 0)

    # Tier 2: installed app runtimes: browsers, Flatpak/Snap apps, /opt apps,
    # Electron apps, AppImages, Discord/Vesktop-like apps.
    if (
        is_app_runtime_path(path)
        and (
            shared_lib
            or executable
            or name.endswith(RUNTIME_SUFFIXES)
            or name in ELECTRON_RUNTIME_NAMES
            or name.endswith(CONFIG_SUFFIXES)
        )
    ):
        confidence = 820
        if path_has_prefix(path, BROWSER_RUNTIME_PREFIXES):
            confidence += 220
        if path_contains_any(path, ELECTRON_APP_SUBSTRINGS):
            confidence += 220
        if name in ELECTRON_RUNTIME_NAMES:
            confidence += 200
        if shared_lib or executable:
            confidence += 160
        return (2, confidence, 0)

    # Tier 3: browser, Vesktop/Discord, OBS, COSMIC, VS Code, Slack user startup state.
    # Cache configs and startup DBs, not random HTTP cache blobs.
    if browser_profile or user_app or cosmic:
        if name in BROWSER_STARTUP_NAMES:
            return (3, 900, 0)

        if name in ELECTRON_RUNTIME_NAMES:
            return (3, 880, 0)

        if name.endswith((".sqlite", ".sqlite3", ".db")) and size <= 256 * MIB:
            return (3, 780, 0)

        if name.endswith(CONFIG_SUFFIXES) or name.endswith(RUNTIME_SUFFIXES):
            return (3, 720, 0)

        if size <= 4 * MIB:
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


def scan_files(cfg: dict, max_file_size: Optional[int]) -> list[FileRec]:
    include_paths = build_include_paths(cfg)
    excludes = [os.path.normpath(p) for p in cfg["exclude_prefixes"]]
    seen_realpaths: set[str] = set()
    files: list[FileRec] = []
    steps = 0

    for root in include_paths:
        if path_is_excluded(root, excludes):
            continue

        try:
            root_dev = os.stat(root).st_dev
        except OSError:
            continue

        stay_on_this_filesystem = (
            cfg.get("stay_on_filesystem", True)
            and not root_allows_cross_filesystem(root, cfg)
        )

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

            if path_is_excluded(dirpath, excludes) or should_prune_dir(dirpath):
                dirnames[:] = []
                continue

            kept_dirs: list[str] = []
            for d in dirnames:
                full = os.path.normpath(os.path.join(dirpath, d))
                full_l = full.lower()

                if path_is_excluded(full, excludes) or should_prune_dir(full_l):
                    continue

                try:
                    st = os.lstat(full)
                except OSError:
                    continue

                if stat.S_ISLNK(st.st_mode):
                    continue

                if stay_on_this_filesystem and st.st_dev != root_dev:
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

                if stay_on_this_filesystem and st.st_dev != root_dev:
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
                files.append(FileRec(path=full, size=size, mtime=st.st_mtime, mode=st.st_mode))

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


def build_selection_order(files: list[FileRec]) -> list[FileRec]:
    ranked: list[tuple[tuple[int, int, int, int, float, str], FileRec]] = []

    for rec in files:
        tier, confidence, _ = classify_file(rec)

        if tier >= 99:
            continue

        # Priority tiers first. Inside each tier:
        # - higher confidence wins
        # - smaller files win
        # - newer files win
        #
        # Tier 5 is the fallback and therefore behaves like the old algorithm:
        # smallest files first, then newer files.
        if tier == 5:
            key = (
                tier,
                fallback_size_rank(rec.size),
                rec.size,
                0,
                -rec.mtime,
                rec.path,
            )
        else:
            key = (
                tier,
                fallback_size_rank(rec.size),
                -confidence,
                rec.size,
                -rec.mtime,
                rec.path,
            )

        ranked.append((key, rec))

    ranked.sort(key=lambda item: item[0])
    return [rec for _, rec in ranked]


def select_files(
    ordered: list[FileRec],
    budget_bytes: int,
    cfg: dict,
) -> list[FileRec]:
    if budget_bytes <= 0:
        return []

    selected: list[FileRec] = []
    total = 0
    steps = 0

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

        # The list is now tier/priority sorted, not globally size-sorted.
        # If one high-priority file does not fit, skip it and keep filling the
        # budget with other useful files.
        if total + rec.size > budget_bytes:
            continue

        selected.append(rec)
        total += rec.size

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

    # Hysteresis watermarks:
    #
    # - target_available_bytes is the hard floor. If MemAvailable falls below
    #   this, shrink immediately.
    #
    # - target_shrink_to_available_bytes is where shrinking aims. This gives
    #   breathing room so the machine does not hover right at the hard floor.
    #
    # - target_grow_above_available_bytes is the upper watermark. The cache only
    #   grows again after MemAvailable clearly rises above this.
    #
    # - target_grow_to_available_bytes is where growth aims. Usually this should
    #   match target_shrink_to_available_bytes.
    floor_available = parse_size(cfg.get("target_available_bytes", "8G")) or (8 * GIB)
    shrink_to_available = (
        parse_size(cfg.get("target_shrink_to_available_bytes", "9G"))
        or (9 * GIB)
    )
    grow_above_available = (
        parse_size(cfg.get("target_grow_above_available_bytes", "10G"))
        or (10 * GIB)
    )
    grow_to_available = (
        parse_size(cfg.get("target_grow_to_available_bytes", "9G"))
        or shrink_to_available
    )

    # Keep the watermarks sane even if the config is edited badly.
    shrink_to_available = max(shrink_to_available, floor_available)
    grow_to_available = max(grow_to_available, shrink_to_available)
    grow_above_available = max(grow_above_available, grow_to_available)

    def target_for_available_reserve(reserve_bytes: int) -> int:
        # Control against the controller's current selected cache budget, not
        # only Mlocked.
        #
        # Mlocked is useful status data, but it can understate the controller's
        # effective cache target and it does not always move MemAvailable
        # one-for-one on large systems. If MemAvailable is still above the
        # grow watermark, grow from the current selected target by the extra
        # available headroom.
        #
        # Example:
        #   current target: 42G
        #   MemAvailable: 21G
        #   desired reserve: 5G
        #   next target: 42G + (21G - 5G) = 58G
        baseline = int(current_target_bytes) if current_target_bytes is not None else locked_now
        target = baseline + available - reserve_bytes

        # This is a file-selection budget, not guaranteed real locked RAM.
        # On large systems, selected logical file bytes can be much larger than
        # the pages that actually become Mlocked. Capping this at MemTotal can
        # strand lots of available RAM unused.
        selection_budget_cap = parse_size(cfg.get("max_selection_budget_bytes"))
        if selection_budget_cap is None:
            selection_budget_cap = int(
                total * float(cfg.get("max_selection_budget_total_ratio", 4.0))
            )

        return max(0, min(int(target), int(selection_budget_cap)))

    initial_cap = parse_size(cfg.get("target_initial_max_bytes", "4G"))
    grow_step_cap = parse_size(cfg.get("target_max_grow_step_bytes", "2G"))

    if current_target_bytes is None:
        # First run / dead vmtouch / unknown state:
        # Do NOT jump straight to MemAvailable - reserve. That can start a huge
        # number of vmtouch locks before the next control loop sees pressure.
        target_bytes = target_for_available_reserve(grow_to_available)

        if initial_cap is not None and initial_cap > 0:
            target_bytes = min(target_bytes, int(initial_cap))

    elif available < floor_available:
        # Memory pressure: shrink immediately and overshoot back to the safer
        # reserve. This avoids bouncing around the 8G line.
        target_bytes = target_for_available_reserve(shrink_to_available)

    elif available > grow_above_available:
        # Plenty of headroom: grow again, but rate-limit growth so startup and
        # rescans ramp instead of slamming RAM all at once.
        target_bytes = target_for_available_reserve(grow_to_available)

        if grow_step_cap is not None and grow_step_cap > 0:
            target_bytes = min(
                target_bytes,
                int(current_target_bytes) + int(grow_step_cap),
            )

    else:
        # Hysteresis band: do nothing. Keep the existing target.
        target_bytes = int(current_target_bytes)

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
    # is enough to prevent churn while still converging toward the 5G reserve.
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
        self.dirty_event = threading.Event()

    def _write_watch_list(self, cfg: dict) -> None:
        WATCH_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
        lines = []
        for p in build_include_paths(cfg):
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



def start_vmtouch(cfg: dict, max_file_size_bytes: Optional[int], records: list[FileRec]) -> VmtouchRun:
    paths = [r.path for r in records]
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


def record_identity(rec: FileRec) -> tuple[str, int, float]:
    return (rec.path, rec.size, rec.mtime)


def common_prefix_len(a: list[FileRec], b: list[FileRec]) -> int:
    limit = min(len(a), len(b))
    idx = 0

    while idx < limit and record_identity(a[idx]) == record_identity(b[idx]):
        idx += 1

    return idx


def stop_vmtouch_runs(runs: list[VmtouchRun]) -> None:
    for run in reversed(runs):
        stop_proc(run)
    runs.clear()


def chunk_selected_records(selected: list[FileRec], cfg: dict) -> list[list[FileRec]]:
    # Smaller chunks make shrink more surgical. 256M means shrink usually
    # releases only what it needs plus at most roughly one chunk.
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


def start_vmtouch_chunks(
    cfg: dict,
    max_file_size_bytes: Optional[int],
    selected: list[FileRec],
) -> list[VmtouchRun]:
    runs: list[VmtouchRun] = []

    for chunk in chunk_selected_records(selected, cfg):
        if chunk:
            runs.append(start_vmtouch(cfg, max_file_size_bytes, chunk))

    return runs


def sync_vmtouch_cache(
    runs: list[VmtouchRun],
    desired: list[FileRec],
    cfg: dict,
    max_file_size_bytes: Optional[int],
) -> tuple[list[VmtouchRun], list[FileRec]]:
    current = flatten_run_records(runs)

    if [record_identity(r) for r in current] == [record_identity(r) for r in desired]:
        return runs, current

    current_bytes = run_bytes(runs)
    desired_bytes = selected_bytes(desired)

    # Shrink path: do NOT rebuild. Just drop tail chunks until the locked cache
    # is under the desired budget. Because build_selection_order() puts small
    # and high-priority files earlier, tail chunks are the correct things to
    # discard first under pressure.
    if desired_bytes < current_bytes:
        while runs and run_bytes(runs) > desired_bytes:
            run = runs.pop()
            stop_proc(run)

        return runs, flatten_run_records(runs)

    prefix = common_prefix_len(current, desired)

    # Grow path: if the desired cache extends the current cache, append only
    # the new suffix chunks.
    if prefix == len(current):
        extra = desired[prefix:]
        for chunk in chunk_selected_records(extra, cfg):
            if chunk:
                runs.append(start_vmtouch(cfg, max_file_size_bytes, chunk))

        return runs, flatten_run_records(runs)

    # Reorder/config/rescan path: full rebuild only when the desired file order
    # changed in a non-prefix way. This should be caused by rescans/config
    # changes, not normal memory-pressure shrink.
    stop_vmtouch_runs(runs)
    runs.extend(start_vmtouch_chunks(cfg, max_file_size_bytes, desired))
    return runs, flatten_run_records(runs)

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
    ordered: list[FileRec] = []
    current_target_bytes: Optional[int] = None
    current_vmtouch_runs: list[VmtouchRun] = []
    current_selected: list[FileRec] = []
    last_full_scan = 0.0
    last_dirty_scan = 0.0

    while RUNNING:
        try:
            config_text, cfg = load_config()
            config_changed = config_text != current_config_text
            if config_changed or watcher.dead():
                current_config_text = config_text
                watcher.start(cfg)

            meminfo = parse_meminfo()
            max_file_size_bytes = resolve_vmtouch_max_file_size_bytes(meminfo, cfg)

            now = time.time()
            dirty_rescan_interval = int(cfg.get("dirty_rescan_interval_seconds", 1800))
            dirty_scan_due = (
                watcher.is_dirty()
                and now - last_dirty_scan >= dirty_rescan_interval
            )

            need_scan = (
                config_changed
                or not inventory
                or watcher.dead()
                or dirty_scan_due
                or now - last_full_scan >= int(cfg.get("full_rescan_interval_seconds", 86400))
            )

            if need_scan:
                inventory = scan_files(cfg, max_file_size_bytes)
                ordered = build_selection_order(inventory)
                last_full_scan = now
                if watcher.is_dirty():
                    last_dirty_scan = now
                watcher.mark_clean()

            any_vmtouch_dead = any(run.poll() is not None for run in current_vmtouch_runs)
            active_target_bytes = current_target_bytes

            if not current_vmtouch_runs or any_vmtouch_dead:
                active_target_bytes = None

            desired_target_bytes, _, _ = choose_target_bytes(meminfo, cfg, active_target_bytes)

            effective_target_bytes = current_target_bytes
            if target_change_is_meaningful(current_target_bytes, desired_target_bytes, cfg):
                effective_target_bytes = desired_target_bytes
            if effective_target_bytes is None:
                effective_target_bytes = desired_target_bytes

            desired_selected = select_files(ordered, effective_target_bytes, cfg)
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
            current_locked_bytes = selected_bytes(current_selected)

            write_status(
                bytes_to_gib(current_locked_bytes),
                current_selected,
                meminfo,
                last_full_scan,
            )

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

  "check_interval_seconds": 3,
  "dirty_rescan_interval_seconds": 1800,
  "full_rescan_interval_seconds": 86400,

  "target_available_bytes": "5G",
  "target_shrink_to_available_bytes": "6G",
  "target_grow_above_available_bytes": "7G",
  "target_grow_to_available_bytes": "6G",

  "target_initial_max_bytes": "4G",
  "target_max_grow_step_bytes": "2G",

  "vmtouch_chunk_target_bytes": "256M",
  "vmtouch_chunk_max_paths": 4096,
  "max_selection_budget_total_ratio": 4.0,

  "target_relock_min_delta": "1G",
  "target_relock_min_delta_ratio": 0.07,

  "fd_limit_reserve": 65536,
  "fd_limit_auto_max": 8388608,
  "memlock_limit_reserve": "1G",
  "memlock_limit_min": "1G",

  "vmtouch_max_file_size": "128G",
  "vmtouch_feed_pause_seconds": 0.005,
  "vmtouch_feed_target_extra_seconds": 10
}
JSON
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
  write_config
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

  systemctl stop ramcache-controller.service || true
  systemctl kill ramcache-controller.service --kill-who=all || true
  systemctl disable ramcache-controller.service || true

  rm -f /etc/systemd/system/ramcache-controller.service
  rm -rf /opt/ramcache-controller
  rm -rf /etc/ramcache-controller
  rm -rf /run/ramcache-controller
  rm -f /etc/sysctl.d/99-ramcache-inotify.conf

  systemctl daemon-reload
  systemctl reset-failed ramcache-controller.service || true
  sysctl --system >/dev/null || true

  echo
  echo "Removed ramcache-controller."
  echo "Removed:"
  echo "  /etc/ramcache-controller"
  echo "  /opt/ramcache-controller"
  echo "  /run/ramcache-controller"
  echo "  /etc/systemd/system/ramcache-controller.service"
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
