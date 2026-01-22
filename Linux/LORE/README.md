## Script Concept: **LORE (Living-Off-Restricted-Environment Enumerator)**

**Purpose:**
A *single-file*, *no-dependencies*, *POSIX-sh–compatible* enumeration script that operates in **highly constrained Linux environments** (no package manager, no Python/Perl/Ruby, no outbound network, minimal binaries).

---

## Design Constraints (Intentional)

* **Shell:** `/bin/sh` only (no Bashisms)
* **Dependencies:** Coreutils + procfs/sysfs only
* **No writes** to disk (stdout only, optional env-based buffering)
* **No outbound network**
* **Graceful degradation** if commands are missing
* **Readable output** even without `less`, `column`, etc.

---

## Core Idea

Instead of traditional “run many commands,” the script:

1. **Discovers what primitives exist**
2. **Dynamically adapts execution paths**
3. **Extracts high-value security context**
4. **Infers misconfigurations through correlation**, not exploits

This makes it viable in:

* hardened containers
* minimal distros (BusyBox, Alpine)
* restricted shells
* jump hosts
* CI/CD runners

---

## Functional Modules

### 1. Capability Fingerprinting (The Differentiator)

Before enumeration, the script builds a **capability map**:

* Available binaries (`command -v`)
* Writable locations (non-destructive tests)
* Shell features (subshells, redirection)
* Presence of `/proc`, `/sys`, `/run`

This lets the script *adapt* rather than fail.

**Example logic (conceptual):**

* If `ss` missing → fall back to `/proc/net/*`
* If `ps` missing → walk `/proc/[0-9]/stat`
* If `id` missing → parse `/proc/self/status`

---

### 2. Identity & Privilege Context

High-signal, low-noise checks:

* UID/GID, groups
* Capabilities (`CapEff`, `CapPrm`)
* SELinux/AppArmor status
* Sudo rules *without invoking sudo*
* Setuid/setgid binaries (stat-based, not `find /`)

Correlation examples:

* Non-root UID + `cap_sys_admin`
* Docker container + writable `/var/run/docker.sock`
* Systemd present + writable unit directories

---

### 3. Process & Service Inference (Without ps/netstat)

Focus on *what matters*, not full listings:

* Long-running root processes
* Credential-handling processes (ssh, dbus, agents)
* Environment variable leaks via `/proc/*/environ`
* Listening services inferred from `/proc/net/tcp*`

This works even when:

* `ps`, `netstat`, `ss`, `lsof` are blocked

---

### 4. Filesystem Trust Boundaries

Rather than brute-force searching:

* Writable directories owned by root but writable by user group
* World-writable executables in `$PATH`
* Cron directories and timers (systemd fallback)
* Mount options (`nosuid`, `nodev`, `noexec`)

Inference > scanning.

---

### 5. Container / VM / CI Detection

Low-noise heuristics:

* cgroup patterns
* overlayfs usage
* hostname entropy
* `/run/secrets` presence
* cloud-init artifacts

This helps assess *escape relevance* without attempting one.

---

### 6. Output Encoding for Exfil-Restricted Environments

Since you mentioned “virtual rubber ducky”-style tooling:

* Optional **environment-variable chunking**
* Base64 or hex output *without base64 binary*
* Deterministic section markers for copy-paste recovery
* Line-length control for terminal logging systems

No file writes required.

---


## Optional Extensions

* **One-line deployable version** (stdin-only)
* **Environment-driven feature flags** (`LORE_MINIMAL=1`)
* **Checksum-based integrity self-check**
* **JSON-ish output using shell only** (key=value)
