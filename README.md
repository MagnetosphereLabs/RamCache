## Install

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s install
````

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s uninstall
```

# An Adaptive and Preemptive RAM Cache Controller for Linux

This project installs a small systemd managed Python controller that continuously selects useful files, feeds them to `vmtouch`, and keeps those files resident in RAM while preserving a configurable amount of available memory for normal system use.

It is designed for desktop Linux systems where application launch latency, game startup latency, Steam/Proton responsiveness, browser startup, desktop shell responsiveness, shader-cache reuse, and general loading speeds matter.

> This is not a tmpfs copy system. It does not move files, duplicate files, replace your filesystem, or rewrite application data. It uses the Linux page cache and `mlock()` behavior through `vmtouch` to keep selected file backed pages resident in RAM.

---

## Table of contents

* [What it does](#what-it-does)
* [Why it exists](#why-it-exists)
* [How it differs from normal Linux caching](#how-it-differs-from-normal-linux-caching)
* [Why it is faster](#why-it-is-faster)
* [How it works](#how-it-works)
* [Architecture](#architecture)

---

## What it does

This RAM Cache Controller keeps selected files hot in memory by:

1. Scanning configured filesystem roots.
2. Excluding unsafe, temporary, huge, or low value paths.
3. Automatically discovering common app/runtime locations.
4. Classifying files into priority tiers.
5. Building a sorted cache candidate list.
6. Choosing how much RAM can be used without crossing configured memory reserve limits.
7. Feeding selected paths to `vmtouch`.
8. Locking those file backed pages into RAM.
9. Shrinking quickly when memory pressure appears.
10. Growing again when the system has enough available memory.
11. Watching the filesystem for changes and rescanning when needed.

The controller is intentionally biased toward files that usually affect perceived desktop speed:

* Core binaries
* Shared libraries
* Dynamic linker data
* Runtime files
* Graphics/audio stack libraries
* Vulkan/Mesa/OpenGL/PipeWire/ALSA/GStreamer support files
* Desktop shell support files
* Fonts
* Icons
* MIME databases
* `.desktop` entries
* Browser startup state
* Electron app runtime files
* Discord/Vesktop/OBS/COSMIC-related files
* Steam startup files
* Steam manifests
* Proton/Wine/Steam runtime files
* Shader caches
* VR/runtime paths
* Lots of small files that are slow to read from an SSD

---

## Why it exists

Normal Linux caching is excellent, but it is reactive. The kernel usually caches file data after it has been read. That means the first launch after boot, after cache eviction, or after heavy I/O can still pay the cost of storage latency.

This project changes the strategy from:

> “Wait until applications read files, then keep recently used pages if memory allows.”

Into:

> “Proactively identify files likely to matter for responsiveness, load them into the page cache, lock them there, and adapt the locked set as memory availability changes.”

The goal is not to replace the Linux page cache. The goal is to steer it toward the files that matter most for interactive desktop performance.

---

## How it differs from normal Linux caching

### Normal Linux page cache

When an application reads a file, the kernel can keep that data in RAM so future reads are faster. This is why “free RAM” on Linux is often low over time while “available RAM” remains healthy.

Normal page cache behavior is mostly:

* Demand driven: files are cached after they are accessed.
* Recency/frequency influenced: recently or repeatedly used pages are more likely to stay hot.
* Reclaimable: cached file pages can be evicted when memory is needed elsewhere.
* Workload dependent: a large read, update, game install, browser cache burst, backup job, or package operation can disturb the useful working set.
* Not application aware: the kernel does not know that one small shared library or shader cache may matter more to perceived responsiveness than a large file read once.

### Our RAM Cache Controller

RAM Cache Controller is different because it is:

* Proactive: it scans and preloads files before applications ask for them.
* Priority based: it ranks files by likely launch/runtime value.
* Desktop aware: it has explicit knowledge of Linux desktop, browser, Steam, Proton, Flatpak, Snap, shader, runtime, and application paths.
* Memory reserve aware: it grows and shrinks based on `MemAvailable` watermarks.
* Locking based: it uses `vmtouch -l`, which keeps selected file backed pages resident until released.
* Chunked: it splits the locked set into smaller groups so shrink operations can release RAM quickly and surgically.
* Adaptive: it watches filesystem changes and periodically rescans.

### Practical difference

Normal Linux caching says:

```text
Application launches -> files are read -> cache becomes warm -> later launches are faster
```

RAM Cache Controller says:

```text
System boots -> useful files are selected and locked -> application launches hit RAM immediately
```

That is the key difference.

---

## Why it is faster

This software can improve speed because many desktop and game launch workloads are bottlenecked by many small file reads:

* Shared libraries
* Loader metadata
* Config files
* Runtime manifests
* Fonts
* Icons
* MIME databases
* Shader caches
* Steam manifests
* Proton/Wine support files
* Electron runtime files
* Browser profile startup databases

Even on fast NVMe storage, thousands of metadata lookups and small reads can add latency. Serving those reads from RAM is faster than going to disk.

The controller improves this by doing three things normal caching does not guarantee:

1. **Prewarming**: important files are loaded before they are needed.
2. **Retention**: important files are locked so unrelated file I/O does not evict them.
3. **Selection**: RAM is spent on files likely to improve interactivity, not random recently read data.

This is especially useful after login, after package updates, after game updates, after opening large files, or after workloads that would normally push useful cached pages out of RAM.

---

## How it works

At a high level, the controller loop does this:

```text
load config
start or refresh filesystem watcher
read /proc/meminfo
compute max allowed file size
scan files
rank files by usefulness
compute desired locked cache size
select files up to the target size
raise file descriptor and memlock limits if needed
start/stop vmtouch processes to match the desired cache
write status JSON
sleep briefly
repeat
```

The controller runs continuously under systemd.

---

## Architecture

The project has three main parts:

### 1. Bash installer

The outer shell script handles:

* Root check
* Dependency installation through `apt`
* Writing the Python controller
* Writing the default JSON config
* Writing the systemd unit
* Writing sysctl tuning files
* Reloading systemd
* Enabling and starting the service
* Status reporting
* Uninstallation

Supported actions:

```bash
sudo ./ramcache-controller.sh install
sudo ./ramcache-controller.sh uninstall
./ramcache-controller.sh status
```

### 2. Python controller

Installed to:

```text
/opt/ramcache-controller/ramcache_controller.py
```

The Python controller performs the actual adaptive cache management:

* Reads `/etc/ramcache-controller/config.json`
* Parses `/proc/meminfo`
* Scans include paths
* Applies exclusions and pruning rules
* Discovers common app paths
* Classifies files
* Selects files for the current memory budget
* Starts `vmtouch` workers
* Chunks the selected set
* Watches filesystem changes with `inotifywait`
* Shrinks under memory pressure
* Grows when memory is available
* Writes status to `/run/ramcache-controller/status.json`

### 3. systemd service

Installed to:

```text
/etc/systemd/system/ramcache-controller.service
```

The service runs:

```text
/usr/bin/python3 /opt/ramcache-controller/ramcache_controller.py
```

It runs as root because it needs to:

* Lock memory.
* Raise resource limits.
* Read system and user app paths.
* Manage child `vmtouch` processes.
* Write runtime status under `/run`.
* Use system level inotify and sysctl configuration.

---

## Installed files

Installation creates or modifies these paths:

```text
/opt/ramcache-controller/ramcache_controller.py
/etc/ramcache-controller/config.json
/etc/systemd/system/ramcache-controller.service
/etc/sysctl.d/99-ramcache-inotify.conf
/etc/sysctl.d/99-cache-aggressive.conf
```

The script only creates `/etc/sysctl.d/99-cache-aggressive.conf` if that file does not already exist.

---

## Runtime files

At runtime, the controller writes:

```text
/run/ramcache-controller/status.json
/run/ramcache-controller/watch-list.txt
```

These are runtime files and are not persistent across reboot.

---

## Dependencies

The installer installs:

```text
python3
vmtouch
inotify-tools
```

The install script uses `apt`, so the current installer is intended for Debian, Ubuntu, Pop!_OS, and similar apt based systems.

---

## Installation

Save the script, make it executable, and run:

```bash
chmod +x ramcache-controller.sh
sudo ./ramcache-controller.sh install
```

The installer will:

1. Install dependencies.
2. Write the controller to `/opt/ramcache-controller`.
3. Write config to `/etc/ramcache-controller/config.json`.
4. Write the systemd unit.
5. Write sysctl tuning files.
6. Apply sysctl settings.
7. Reload systemd.
8. Enable and start the service.

Check service status:

```bash
systemctl status ramcache-controller.service --no-pager
```

Check controller status:

```bash
python3 -m json.tool /run/ramcache-controller/status.json
```

---

## Uninstallation

Run:

```bash
sudo ./ramcache-controller.sh uninstall
```

Uninstall will:

* Stop the service.
* Kill remaining service processes if needed.
* Disable the service.
* Remove the systemd unit.
* Remove `/opt/ramcache-controller`.
* Remove `/etc/ramcache-controller`.
* Remove `/run/ramcache-controller`.
* Remove `/etc/sysctl.d/99-ramcache-inotify.conf`.
* Reload systemd.
* Reset failed service state.
* Re apply sysctl settings.

---

## Status and monitoring

Run:

```bash
./ramcache-controller.sh status
```

Or manually inspect:

```bash
systemctl status ramcache-controller.service --no-pager
python3 -m json.tool /run/ramcache-controller/status.json
grep -E 'MemAvailable|Cached|Active\(file\)|Inactive\(file\)|Mlocked|Unevictable' /proc/meminfo
```

---

## Configuration

The config file is:

```text
/etc/ramcache-controller/config.json
```

Default config:

```json
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

  "check_interval_seconds": 1,
  "dirty_rescan_interval_seconds": 10800,
  "full_rescan_interval_seconds": 86400,

  "target_available_bytes": "7G",
  "target_shrink_to_available_bytes": "8G",
  "target_grow_above_available_bytes": "9G",
  "target_grow_to_available_bytes": "8G",

  "target_initial_max_bytes": "8G",
  "target_max_grow_step_bytes": "4G",
  "target_max_inflight_bytes": "8G",

  "vmtouch_chunk_target_bytes": "512",
  "vmtouch_chunk_max_paths": 8192,
  "max_selection_budget_total_ratio": 4.0,

  "target_relock_min_delta": "1G",
  "target_relock_min_delta_ratio": 0.07,

  "fd_limit_reserve": 65536,
  "fd_limit_auto_max": 8388608,
  "memlock_limit_reserve": "1G",
  "memlock_limit_min": "1G",

  "vmtouch_max_file_size": "128G",
  "vmtouch_feed_pause_seconds": 0,
  "vmtouch_feed_target_extra_seconds": 0
}
```

### Size values

Size values may be written as numbers or strings with suffixes:

```text
K, KB
M, MB
G, GB
T, TB
```

Examples:

```json
"target_available_bytes": "5G"
"vmtouch_chunk_target_bytes": "256M"
"memlock_limit_reserve": "1G"
```

---

## File discovery

The controller starts from `include_paths`.

Default:

```json
"include_paths": ["/", "/home"]
```

It then optionally adds common app paths when enabled:

```json
"auto_include_common_app_paths": true
```

Auto discovered paths include existing directories under locations such as:

* `/opt`
* `/usr/local/bin`
* `/usr/local/lib`
* `/usr/local/libexec`
* `/snap`
* `/var/lib/flatpak/app`
* `/var/lib/flatpak/runtime`
* `/var/lib/flatpak/exports`
* `/var/lib/snapd/desktop`
* User `.local` app paths
* User Flatpak paths
* Browser profile directories
* Discord/Vesktop/OBS/VS Code/VSCodium config paths
* COSMIC desktop config paths
* Fontconfig cache
* Mesa shader cache
* NVIDIA cache
* Steam directories
* Flatpak Steam directories
* Steam library folders discovered from `libraryfolders.vdf`

The controller deduplicates paths and avoids walking redundant child paths when a parent already covers the same filesystem.

---

## File classification and priority tiers

The controller does not blindly lock everything. Every file is classified into a priority tier.

### Tier 0: core OS and runtime foundation

Examples:

* `/bin`
* `/sbin`
* `/lib`
* `/lib64`
* `/etc`
* `/usr/bin`
* `/usr/sbin`
* `/usr/lib`
* `/usr/lib64`
* `/usr/libexec`
* `/usr/local/bin`
* `/usr/local/lib`
* `/usr/local/libexec`

Preferred file types:

* Shared libraries
* Executables
* Config files
* Runtime files
* Dynamic linker data
* Graphics/audio runtime files
* OBS related runtime files
* COSMIC related runtime files

This tier receives the highest priority because these files affect many programs.

### Tier 1: Steam, Proton, Wine, game, shader, and VR launch path

Examples:

* Steam startup files
* Steam manifests
* Proton files
* Wine support files
* Steam Linux Runtime files
* Steam shader cache
* Steam compatibility data
* VR runtime paths
* OpenVR/SteamVR/WiVRn/Monado/ALVR related paths

Special high value names include:

```text
libraryfolders.vdf
config.vdf
loginusers.vdf
shortcuts.vdf
localconfig.vdf
system.reg
user.reg
userdef.reg
```

This tier is optimized for faster Steam startup, faster game launch preparation, and faster Proton/Wine runtime access.

### Tier 2: installed app runtimes

Examples:

* Browser runtimes
* Flatpak app runtimes
* Snap apps
* `/opt` apps
* Electron app runtimes
* AppImage like runtime files

Preferred files include:

* Shared libraries
* Executables
* Runtime blobs
* Electron files such as `app.asar`
* Configuration files

### Tier 3: user app startup state

Examples:

* Firefox profile startup files
* Chromium/Chrome/Brave/Vivaldi/Opera config paths
* Discord/Vesktop config
* OBS config
* VS Code/VSCodium config
* Slack like app config
* COSMIC user config

Preferred browser startup names include:

```text
prefs.js
sessionstore.jsonlz4
extensions.json
addons.json
compatibility.ini
profiles.ini
places.sqlite
favicons.sqlite
permissions.sqlite
cookies.sqlite
storage.sqlite
```

The controller intentionally avoids broad browser HTTP cache directories unless they are shader related.

### Tier 4: desktop support files

Examples:

* Application launchers
* AppStream/metainfo data
* Desktop directories
* Icons
* Pixmaps
* MIME databases
* GLib schemas
* D-Bus data
* systemd unit metadata
* Polkit data
* Fonts
* Themes
* Sounds
* Thumbnailer definitions
* Wayland/X11 session data
* Vulkan data
* PipeWire/PulseAudio/ALSA/GStreamer support files
* KDE/GNOME/Cinnamon/MATE/XFCE support files
* Fontconfig cache

This tier helps with desktop shell startup, app menus, file pickers, icon loading, font discovery, and settings tools.

### Tier 5: fallback

After higher value files are selected, remaining RAM can be filled with other safe small files.

Tier 5 is sorted to prefer smaller files first. This helps systems with limited cache budget get many useful cache hits instead of spending the budget on a few huge files.

### Hard cold exclusions

Some files and directories are skipped or deprioritized because they are unlikely to improve responsiveness or may waste too much RAM.

Examples:

* Documentation trees
* Manual pages
* Source trees
* Logs
* Crash dumps
* Docker/container data
* libvirt data
* Flatpak repo storage
* Snap package cache
* Browser HTTP cache blobs
* Trash
* VCS metadata such as `.git`
* Build directories such as `target/debug` and `target/release`
* Huge media files
* Huge documents
* Huge package images
* Huge archives
* Huge game asset packs
* Huge AppImage/bin blobs

---

## Memory targeting

The controller computes a target from current memory availability.

It reads:

```text
/proc/meminfo
```

Important fields:

* `MemTotal`
* `MemAvailable`
* `Cached`
* `Active(file)`
* `Inactive(file)`
* `Mlocked`
* `Unevictable`

The default memory watermarks are:

```json
"target_available_bytes": "5G",
"target_shrink_to_available_bytes": "7G",
"target_grow_above_available_bytes": "8G",
"target_grow_to_available_bytes": "7G"
```

Meaning:

| Setting                             | Meaning                                                                               |
| ----------------------------------- | ------------------------------------------------------------------------------------- |
| `target_available_bytes`            | Hard lower available memory floor. If `MemAvailable` falls below this, shrink cache.  |
| `target_shrink_to_available_bytes`  | When shrinking, release enough cache to recover to this safer available memory level. |
| `target_grow_above_available_bytes` | Only grow when `MemAvailable` rises above this upper watermark.                       |
| `target_grow_to_available_bytes`    | When growing, leave approximately this much memory available.                         |

Default behavior:

```text
Below 5G available  -> shrink
5G to 8G available  -> hold steady
Above 8G available  -> grow, while trying to leave about 7G available
```

This prevents constant grow/shrink churn.

---

## Growth, shrink, and hysteresis

The controller uses hysteresis to avoid unstable behavior.

### Initial target

Default:

```json
"target_initial_max_bytes": "8G"
```

On first startup, the controller caps the first target so the system can ramp up safely.

### Grow step

Default:

```json
"target_max_grow_step_bytes": "4G"
```

When there is extra memory, the cache grows in bounded steps instead of trying to jump to the full possible target at once.

### Grow deadband

Default:

```json
"target_relock_min_delta": "1G"
```

Small target increases are ignored. This prevents relocking for tiny changes.

### Shrink behavior

Shrink is immediate when the available memory floor is crossed.

If memory pressure appears, the controller drops tail chunks from the selected set. Since the selected list is priority ordered, tail chunks are lower priority than the earlier chunks.

This means the controller tries to preserve the most valuable files while releasing RAM.

---

## vmtouch locking model

The controller starts `vmtouch` like this:

```text
vmtouch -q -l -0 -b - -m <max-file-size>
```

The important options are:

| Option | Purpose                                    |
| ------ | ------------------------------------------ |
| `-q`   | Quiet output.                              |
| `-l`   | Lock touched pages in memory.              |
| `-0`   | Read null-delimited path input.            |
| `-b -` | Read paths from standard input.            |
| `-m`   | Set maximum file size accepted by vmtouch. |

The Python controller feeds selected file paths to `vmtouch` through stdin.

Each `vmtouch` process keeps its selected files resident while it remains running. When the controller needs to release RAM, it terminates selected `vmtouch` processes. The locked pages then become releasable by the kernel.

---

## Chunking model

The selected file list is split into chunks.

Defaults:

```json
"vmtouch_chunk_target_bytes": "256M",
"vmtouch_chunk_max_paths": 4096
```

Chunking matters because it makes shrink operations faster and more precise.

Instead of one massive `vmtouch` process holding the entire cache, the controller runs multiple smaller `vmtouch` processes. Under memory pressure, it can stop only the tail chunks needed to recover memory.

Benefits:

* Faster RAM release.
* Less over shrinking.
* Better preservation of high priority files.

---

## Filesystem behavior

Default:

```json
"stay_on_filesystem": true
```

When enabled, the scanner does not cross filesystem boundaries while walking a root path. This prevents accidentally scanning mounted drives, network mounts, external disks, special mounts, or unrelated filesystems.

Exception roots can be configured:

```json
"cross_filesystem_include_roots": ["/snap"]
```

This lets selected roots cross filesystem boundaries when needed.

The scanner also avoids symlink traversal:

```text
followlinks=False
```

This reduces duplicate scanning and prevents symlink loops.

---

## Inotify watcher behavior

The controller uses `inotifywait` to monitor configured include paths and exclusions.

It writes a watch list to:

```text
/run/ramcache-controller/watch-list.txt
```

The watcher listens for:

```text
close_write
create
delete
move
attrib
```

When a change occurs, the watcher marks the cache inventory dirty. The controller does not necessarily rescan instantly. It waits for the dirty rescan interval.

Default:

```json
"dirty_rescan_interval_seconds": 1800
```

A full rescan also occurs periodically.

Default:

```json
"full_rescan_interval_seconds": 86400
```

This design avoids constantly rescanning during active package installs, Steam updates, browser activity, or build workloads.

---

## System limits

Large cache selections may require many file descriptors and a large memlock limit.

The controller tries to raise:

* `RLIMIT_NOFILE`
* `RLIMIT_MEMLOCK`
* `/proc/sys/fs/nr_open`
* `/proc/sys/fs/file-max`

Relevant config:

```json
"fd_limit_reserve": 65536,
"fd_limit_auto_max": 8388608,
"memlock_limit_reserve": "1G",
"memlock_limit_min": "1G"
```

The systemd unit also sets:

```text
LimitNOFILE=infinity
LimitMEMLOCK=infinity
```

---

## Sysctl changes

The installer writes:

```text
/etc/sysctl.d/99-ramcache-inotify.conf
```

With:

```text
fs.inotify.max_user_watches=1048576
```

This allows recursive watching of large directory trees.

The installer may also write:

```text
/etc/sysctl.d/99-cache-aggressive.conf
```

With:

```text
vm.vfs_cache_pressure=10
vm.vfs_cache_pressure_denom=100
```

This asks the kernel to be less aggressive about reclaiming filesystem metadata caches. The installer only creates this file if it does not already exist.

---

## Performance expectations

Expected improvements are usually in perceived responsiveness:

* Faster application launches.
* Faster Steam/Proton startup path access.
* Faster desktop menu/icon/font/MIME interactions.
* Less "cold cache" behavior on systems with enough spare RAM.

This does not make CPU-bound or GPU-bound work faster.

---

## Systems with lots of RAM

This controller is especially useful on high RAM systems because normal Linux behavior may leave large amounts of RAM available or use it for recently accessed data that is not important for interactivity.

With lots of RAM, the controller can:

* Keep core OS/runtime files hot.
* Keep desktop support files hot.
* Keep browser startup data hot.
* Keep Steam/Proton/Wine launch paths hot.
* Keep shader caches hot.
* Fill extra RAM with lots of small files that storage drive load slowly (random reads).
* Preserve a configured available memory reserve.

The default budget cap is controlled by:

```json
"max_selection_budget_total_ratio": 4.0
```

That is a high ceiling, not a forced allocation. Actual target size is still controlled by available-memory watermarks and grow logic.

For very high-RAM systems, raising the watermarks and grow steps can allow a larger locked cache while still keeping the machine responsive.

---

## Systems with less RAM

The controller can still help on smaller systems because selection is prioritized.

Instead of trying to cache everything, it prefers:

* Core shared libraries
* Executables
* Loader/runtime files
* Small configs
* Desktop metadata
* Browser startup files
* Steam/Proton manifests and runtime files
* Small shader/cache files

The memory floor prevents the cache from consuming RAM needed by applications.

---

## Safety model

The controller is designed to be conservative in these ways:

* It does not modify cached files.
* It does not move application files.
* It does not replace directories with tmpfs mounts.
* It avoids `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, and other unsafe paths by default.
* It does not follow symlinks while scanning.
* It avoids crossing filesystem boundaries by default.
* It skips empty files.
* It skips non regular files.
* It deduplicates real paths.
* It prunes known cold or dangerous directory trees.
* It shrinks immediately under memory pressure.
* It chunks vmtouch workers for faster release.
* It stops all vmtouch workers on service shutdown.

The most important safety feature is the available memory floor. If the system needs RAM, the controller should reduce its locked cache.

---

## Limitations

### Not all workloads benefit

It does not directly accelerate:

* CPU-bound rendering
* GPU-bound games
* Network latency

### Selection is heuristic

The classifier is intentionally opinionated. It knows about common Linux desktop, Steam, Proton, browser, Flatpak, Snap, shader, and runtime patterns. It cannot perfectly know every user’s workload.

### Large files are usually avoided

Huge media files, package images, archives, and monolithic game assets are usually poor locked-cache targets. The controller avoids or deprioritizes them.
