# RamCache Controller

RamCache Controller is a lightweight Linux service that turns spare RAM into a smarter file cache for your system. It proactively builds a large hot working set from files on disk, keeps that set resident with `vmtouch`, watches for file changes, and continuously adjusts its locked cache budget so total system memory usage stays under a configured cap without thrashing on tiny memory fluctuations. This is especially useful on machines with more RAM than they normally use, and on systems where storage is a bottleneck, like DRAM less SSDs, slower SATA SSDs, or older drives.

## What it does

- Preloads files into RAM
- Keeps a large hot file set resident over time
- Adjusts its locked cache size from live memory state
- Keeps total system RAM usage under a configured ceiling
- Ignores small target drift so it does not keep reloading `vmtouch` unnecessarily
- Watches for filesystem changes and refreshes automatically
- Installs as a simple systemd service
- Works well on systems with 16 GB, 32 GB, 64 GB, or more RAM

## How it differs from normal Linux caching

Instead of waiting for the cache to slowly form on its own, it deliberately loads and maintains a much larger hot set of real files in RAM, then trims that set back well before the machine starts needing memory for something more important. It does not replace Linux page cache, but makes it more persistent and makes better use of spare RAM on systems where that is worth it.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s install
````

## Check Status

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s status
```

## Uninstall

```bash
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s uninstall
```

## How it works

The service installs a Python controller, a systemd unit, a default config, and the required packages: `python3`, `vmtouch`, and `inotify-tools`. Once started, the controller runs in a loop and manages a selected set of files that should stay hot in RAM.

Each cycle does four main things. It loads the current config, decides whether the filesystem inventory needs to be rebuilt, reads current memory state from `/proc/meminfo`, and then selects a file set that fits inside the current effective RAM target. Filesystem inventory rebuilds are driven separately from the fast memory control loop, so the controller can check memory pressure frequently without needing to rescan the full filesystem each time. The controller computes a desired target every cycle, but only adopts target changes when they are large enough to matter. If the effective target changes enough to alter the selected set, it restarts `vmtouch` with the new list.

The result is a managed hot file set that stays in sync with both the current filesystem and the machine’s current memory usage.

## How the RAM target works

RamCache Controller does not use a fixed hardcoded amount of memory. It recalculates the allowed locked-cache budget from live memory state every cycle.

It reads `MemTotal`, `MemAvailable`, and `Mlocked` from `/proc/meminfo`.

From that, it computes:

* `working_used = MemTotal - MemAvailable`
* `locked_now = Mlocked`
* `non_cache_used = max(0, working_used - locked_now)`

The controller then derives the desired cache budget from the configured total RAM cap:

* `desired_target_bytes = (MemTotal * max_total_used_ratio) - non_cache_used`

That result is clamped between zero and total system RAM.

With the default config, `max_total_used_ratio` is `0.75`. In practice, that means RamCache tries to use as much memory as possible while keeping total system RAM usage at or below 75 percent. If applications and the rest of the system use more RAM, RamCache shrinks by only the amount needed. If non-cache memory use reaches that cap by itself, RamCache’s target falls to zero.

The controller also applies a deadband before acting on a newly computed target. Small target drift is ignored unless the change crosses a meaningful threshold. By default, a target change must be at least the larger of:

* `512M`
* `3 percent` of the current or desired target

This prevents needless stop/start churn when `/proc/meminfo` moves by small amounts between control-loop passes.

There is also a minimum available memory guard. If `MemAvailable` falls below 12.5 percent of total RAM, the target is forced to zero immediately.

This lets the service stay aggressive when RAM is truly spare, back off automatically when applications need memory, and avoid constantly relaunching `vmtouch` over tiny fluctuations.

## How file discovery works

The controller scans the paths listed in `include_paths` and builds an inventory of eligible files. By default that starts at `/`.

During the scan, it skips excluded prefixes such as `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, and other paths that should not be part of the managed cache set. It only keeps regular files, ignores zero length files, and avoids symlinked directories.

It also deduplicates by real path, so the same underlying file is only considered once even if it appears through multiple visible paths.

During large scans it briefly stops at configurable intervals so long scans across large filesystems stay smoother and less bursty.

## How file selection works

Once the inventory exists, the controller builds two sorted views of it:

* one ordered from smallest file to largest
* one ordered from largest file to smallest

It then selects files against the current RAM budget in three passes.

First, it assigns 70 percent of the budget to the smallest files first. This quickly packs a large number of useful small files into RAM. Small libraries, binaries, scripts, metadata-heavy trees, and lots of small files from your OS and apps can benefit from this because many of those small files can fit into a relatively small amount of memory.

Second, it assigns the remaining 30 percent of the budget to the largest files first. This keeps the cache from becoming overly biased toward only tiny files and lets larger useful files stay hot too.

Third, after those two passes, it fills any remaining space with whatever still fits. That gives the controller a fuller final packing instead of leaving easy caching wins behind.

Selection is based on total file bytes, not file count. If there are many files on disk, the controller scans them all, then chooses the subset whose combined size fits inside the current target. So the cache grows to a calculated cap based on available RAM.

When files are the same size, newer modification time is preferred first, and path provides a stable final tie break.

Large selection passes pause briefly at configurable intervals in the same way scans do.

## How `vmtouch` is managed

After selection, the controller turns the chosen paths into a null separated list and feeds them to `vmtouch` over standard input.

The current version does this through a dedicated feeder thread. That thread can pace the input stream using two config values:

* `vmtouch_feed_pause_seconds`
* `vmtouch_feed_target_extra_seconds`

These settings let the controller spread out part of the feed over a short window instead of dumping the whole path list at once. On large path sets, that makes the handoff to `vmtouch` more controlled.

The controller computes a desired RAM target every cycle, but it only adopts target changes that are large enough to matter. If that effective target changes enough to produce a different selected file list, if the config changes, or if the current `vmtouch` process exits, the controller stops the existing run cleanly and starts a new one with the updated set.

## Watching for changes

RamCache Controller uses `inotifywait` to watch the included paths recursively. It listens for writes, creates, deletes, moves, and attribute changes. When something changes, it marks the inventory as dirty so the controller knows a rebuild is needed.

Watcher driven rebuilds are intentionally rate limited by `dirty_rescan_interval_seconds`. By default, filesystem changes are folded into a rebuild at most once every 30 minutes instead of forcing a full inventory pass on every fast control cycle.

There is also a scheduled full rescan interval. By default the controller forces a full rebuild every 24 hours even if no watch event triggered it.

## Runtime and status

The controller wakes up every `check_interval_seconds`, which is 30 seconds by default in the current version.

On each pass it reads current memory state, recalculates the desired RAM target from `MemTotal`, `MemAvailable`, `Mlocked`, and `max_total_used_ratio`, applies a deadband so tiny target drift is ignored, reselects files from the cached sorted lists using the effective target, and refreshes the running `vmtouch` set only when something materially changed.

Full filesystem inventory rebuilds are handled on a separate schedule. By default, watcher-driven rebuilds are allowed at most once every 30 minutes through `dirty_rescan_interval_seconds`, while a full safety rebuild still runs every 24 hours through `full_rescan_interval_seconds`.

It also writes a status file at:

```text
/run/ramcache-controller/status.json
````

That file includes:

* current target lock size in GiB
* number of selected files
* total selected size in GiB
* memory totals and available memory
* current cached, active file, and inactive file memory
* mlocked and unevictable memory
* last full scan time

This makes it easy to see exactly what the controller is doing at runtime.

## Default configuration

```json
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
  "check_interval_seconds": 30,
  "dirty_rescan_interval_seconds": 1800,
  "full_rescan_interval_seconds": 86400,
  "base_target_ratio": 0.72,
  "min_available_ratio": 0.125,
  "max_total_used_ratio": 0.75,
  "target_relock_min_delta": "512M",
  "target_relock_min_delta_ratio": 0.03,
  "small_files_share_percent": 70,
  "vmtouch_max_file_size_ratio": 0.50,
  "vmtouch_feed_pause_seconds": 0.02,
  "vmtouch_feed_target_extra_seconds": 30,
  "reduce_thresholds": [
    {"working_used_ratio": 0.0, "target_locked_ratio": 0.72},
    {"working_used_ratio": 0.68, "target_locked_ratio": 0.50},
    {"working_used_ratio": 0.75, "target_locked_ratio": 0.36},
    {"working_used_ratio": 0.82, "target_locked_ratio": 0.0}
  ]
}
```

The live RAM-target calculation uses `max_total_used_ratio`, `min_available_ratio`, `target_relock_min_delta`, and `target_relock_min_delta_ratio`.

`base_target_ratio` and `reduce_thresholds` are still present in the generated config file, but the current controller path does not use them when calculating the active RAM target.

## Systemd service

The installer creates a systemd service that starts the controller at boot and keeps it running. It runs as root, restarts automatically, raises the open file descriptor limit, and allows unlimited memory locking so `vmtouch` can keep the selected working set resident.

It also raises `fs.inotify.max_user_watches` and sets a low `vm.vfs_cache_pressure` profile so the kernel stays friendlier to persistent file caching.
