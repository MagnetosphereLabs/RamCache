# RamCache Controller

RamCache Controller is a lightweight Linux service that turns spare RAM into a smarter file cache for your system. It proactively builds a large hot working set from files on disk, keeps that set resident with `vmtouch`, watches for file changes, and automatically scales its cache down when applications need more memory. The result is a system that feels more “preloaded” over time instead of constantly warming up from scratch. This is especially useful on machines with more RAM than they normally use, and on systems where storage is a bottleneck, like DRAM less SSDs, slower SATA SSDs, or older drives.

## What it does

- Preloads real files into RAM
- Keeps a large hot file set resident over time
- Adapts its cache budget to current memory pressure
- Watches for filesystem changes and refreshes automatically
- Installs as a simple systemd service
- Works well on systems with 16 GB, 32 GB, 64 GB, or more RAM

## How it differs from normal Linux caching
Instead of waiting for the cache to slowly form on its own, it deliberately loads and maintains a much larger hot set of real files in RAM, then trims that set back well before the machine starts needing memory for something more important. It does not replace Linux page cache, but makes it more persistent and makes better use of spare RAM on systems where that is worth it.

## Good fit

RamCache Controller makes the most sense when:

- your machine has more RAM than your normal workload needs
- you keep the system running for long periods
- you use the same apps, libraries, toolchains, games, or project files repeatedly
- your storage is noticeably slower than you'd like
- you want the system to feel faster after it has been up for a while

## Install

```
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s install
```

## Check Status
```
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s status
```

## Uninstall
```
curl -fsSL https://raw.githubusercontent.com/MagnetosphereLabs/RamCache/main/ramcache.sh | sudo bash -s uninstall
```
