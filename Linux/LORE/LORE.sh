#!/bin/sh
# LORE (Living-Off-Restricted-Environment Enumerator)
# Version: 1.0
# POSIX-sh compatible enumeration for highly constrained Linux environments
# Usage: sh lore.sh [options]
# Options:
#   LORE_BASE64=1     - Base64 encode output
#   LORE_HEX=1        - Hex encode output

set -e 2>/dev/null || true  # Continue on errors

# ============================================================================
# GLOBAL STATE
# ============================================================================

LORE_VERSION="1.0"
LORE_START_TIME=""
CAPABILITY_MAP=""
SEPARATOR="========================================"
OUTPUT_BUFFER=""
USE_BUFFER=0

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Initialize buffering if needed
init_output() {
    if [ -n "$LORE_BASE64" ] || [ -n "$LORE_HEX" ]; then
        USE_BUFFER=1
    fi
}

# Buffer or print
buf_append() {
    nl='
'
    output="$1$nl"
    if [ "$USE_BUFFER" = "1" ]; then
        OUTPUT_BUFFER="${OUTPUT_BUFFER}${output}"
    else
        printf "%s" "$output"
    fi
}

# Safe command check
has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

# Output formatting
section() {
    buf_append "$(printf "\n%s\n[%s]\n%s\n" "$SEPARATOR" "$1" "$SEPARATOR")"
}

info() {
    buf_append "$(printf "  %s\n" "$1")"
}

warn() {
    buf_append "$(printf "  [!] %s\n" "$1")"
}

# Safe file read with fallback
safe_read() {
    if [ -r "$1" ]; then
        cat "$1" 2>/dev/null || printf "unreadable\n"
    else
        printf "not_found\n"
    fi
}

# Safe stat without stat command
safe_stat() {
    if [ -e "$1" ]; then
        if has_cmd stat; then
            stat -c "mode=%a uid=%u gid=%g" "$1" 2>/dev/null
        else
            ls -ld "$1" 2>/dev/null | awk '{print "perms=" $1 " owner=" $3 " group=" $4}'
        fi
    fi
}

# Hex encode without od if missing
hex_encode() {
    if has_cmd od; then
        od -A n -t x1 | tr -d ' \n'
    else
        # Fallback: character-by-character conversion
        awk 'BEGIN {
            for(i=0;i<256;i++) hex[sprintf("%c",i)]=sprintf("%02x",i)
        } {
            for(i=1;i<=length($0);i++) printf "%s", hex[substr($0,i,1)]
            printf "0a"
        }'
    fi
}

# Base64 encode without base64 command if missing
base64_encode() {
    if has_cmd base64; then
        base64 -w 0 2>/dev/null || base64
    else
        # Minimal base64 implementation using awk
        awk 'BEGIN {
            b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        } {
            for(i=1; i<=length($0); i++) {
                buf = buf sprintf("%08d", dec2bin(index($0, substr($0,i,1))))
            }
            buf = buf "000000"
            while(length(buf) >= 6) {
                printf "%s", substr(b64, bin2dec(substr(buf,1,6))+1, 1)
                buf = substr(buf, 7)
            }
        } function dec2bin(n,  r) {
            while(n) { r = (n%2) r; n = int(n/2) }
            return r
        } function bin2dec(b,  n) {
            for(i=1; i<=length(b); i++) n = n*2 + substr(b,i,1)
            return n
        }'
    fi
}

# Flush and encode buffer at end
flush_output() {
    if [ "$USE_BUFFER" = "0" ]; then
        return
    fi
    
    if [ -n "$LORE_BASE64" ]; then
        printf "\n%s\n[Base64 Encoded Output]\n%s\n" "$SEPARATOR" "$SEPARATOR"
        printf "%s" "$OUTPUT_BUFFER" | base64_encode
        printf "\n"
    elif [ -n "$LORE_HEX" ]; then
        printf "\n%s\n[Hex Encoded Output]\n%s\n" "$SEPARATOR" "$SEPARATOR"
        printf "%s" "$OUTPUT_BUFFER" | hex_encode
        printf "\n"
    fi
}

# ============================================================================
# CAPABILITY FINGERPRINTING
# ============================================================================

discover_capabilities() {
    section "Capability Discovery"
    
    CAPABILITY_MAP=""
    
    # Check essential commands
    for cmd in ps netstat ss ip id grep awk sed find stat lsof systemctl docker kubectl; do
        if has_cmd "$cmd"; then
            CAPABILITY_MAP="$CAPABILITY_MAP $cmd"
            info "✓ $cmd"
        fi
    done
    
    # Check filesystem features
    if [ -d /proc ]; then
        info "✓ /proc filesystem"
        CAPABILITY_MAP="$CAPABILITY_MAP procfs"
    fi
    
    if [ -d /sys ]; then
        info "✓ /sys filesystem"
        CAPABILITY_MAP="$CAPABILITY_MAP sysfs"
    fi
    
    # Check shell features
    if ( : ) 2>/dev/null; then
        CAPABILITY_MAP="$CAPABILITY_MAP subshell"
    fi
    
    # Writable locations (non-destructive)
    for dir in /tmp /var/tmp /dev/shm; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            info "✓ writable: $dir"
            CAPABILITY_MAP="$CAPABILITY_MAP writable:$dir"
        fi
    done
    
    info "Capability map: $CAPABILITY_MAP"
}

# ============================================================================
# IDENTITY & PRIVILEGE CONTEXT
# ============================================================================

enumerate_identity() {
    section "Identity & Privilege Context"
    
    # UID/GID
    if has_cmd id; then
        info "User: $(id)"
    elif [ -r /proc/self/status ]; then
        uid=$(grep -E '^Uid:' /proc/self/status | awk '{print $2}')
        gid=$(grep -E '^Gid:' /proc/self/status | awk '{print $2}')
        info "UID: $uid GID: $gid"
    fi
    
    # Current user details
    if [ -r /etc/passwd ]; then
        current_user=$(whoami 2>/dev/null || echo "$USER")
        if [ -n "$current_user" ]; then
            user_line=$(grep "^$current_user:" /etc/passwd 2>/dev/null)
            [ -n "$user_line" ] && info "Passwd entry: $user_line"
        fi
    fi
    
    # Groups
    if has_cmd groups; then
        info "Groups: $(groups)"
    fi
    
    # Linux capabilities
    if [ -r /proc/self/status ]; then
        cap_eff=$(grep -E '^CapEff:' /proc/self/status | awk '{print $2}')
        cap_prm=$(grep -E '^CapPrm:' /proc/self/status | awk '{print $2}')
        cap_inh=$(grep -E '^CapInh:' /proc/self/status | awk '{print $2}')
        
        if [ -n "$cap_eff" ] && [ "$cap_eff" != "0000000000000000" ]; then
            warn "Effective capabilities: $cap_eff"
        fi
        if [ -n "$cap_prm" ] && [ "$cap_prm" != "0000000000000000" ]; then
            warn "Permitted capabilities: $cap_prm"
        fi
        if [ -n "$cap_inh" ] && [ "$cap_inh" != "0000000000000000" ]; then
            warn "Inherited capabilities: $cap_inh"
        fi
    fi
    
    # SELinux
    if [ -r /sys/fs/selinux/enforce ]; then
        selinux_mode=$(cat /sys/fs/selinux/enforce)
        info "SELinux enforcing: $selinux_mode"
    fi
    
    # AppArmor
    if [ -r /sys/kernel/security/apparmor/profiles ]; then
        info "AppArmor profiles loaded: $(wc -l < /sys/kernel/security/apparmor/profiles)"
    fi
    
    # Sudo configuration (without invoking sudo)
    if [ -r /etc/sudoers ]; then
        warn "Sudoers readable!"
        grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' | head -20
    fi
    
    # Check for setuid/setgid binaries in common locations
    section "Setuid/Setgid Binaries (common paths)"
    for dir in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
        if [ -d "$dir" ]; then
            if has_cmd find; then
                find "$dir" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do
                    info "$(safe_stat "$f") $f"
                done
            else
                # Fallback: manual check
                ls -la "$dir" 2>/dev/null | grep '^-..s' | awk '{print $NF}' | while read -r f; do
                    info "$dir/$f"
                done
            fi
        fi
    done
}

# ============================================================================
# PROCESS & SERVICE INFERENCE
# ============================================================================

enumerate_processes() {
    section "Process & Service Analysis"
    
    # List processes using available method
    if has_cmd ps; then
        info "Running processes (root):"
        # ps aux 2>/dev/null | grep '^root' | head -15 || ps -ef | grep '^root' | head -15
        ps_output=$(ps aux 2>/dev/null | grep '^root' | head -15 2>/dev/null || ps -ef | grep '^root' | head -15 2>/dev/null)
        while IFS= read -r line; do
            info "$line"
        done <<EOF
        $ps_output
EOF
    elif [ -d /proc ]; then
        info "Processes via /proc (first 15):"
        count=0
        for pid_dir in /proc/[0-9]*; do
            [ $count -ge 15 ] && break
            pid=$(basename "$pid_dir")
            if [ -r "$pid_dir/cmdline" ]; then
                cmdline=$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null | head -c 100)
                [ -n "$cmdline" ] && info "PID $pid: $cmdline" && count=$((count + 1))
            fi
        done
    fi
    
    # Check for sensitive processes
    if [ -d /proc ]; then
        info "Checking for credential-handling processes:"
        for name in ssh-agent gpg-agent dbus keyring docker containerd; do
            for pid_dir in /proc/[0-9]*; do
                if [ -r "$pid_dir/comm" ]; then
                    comm=$(cat "$pid_dir/comm" 2>/dev/null)
                    if echo "$comm" | grep -q "$name"; then
                        warn "Found: $name (PID $(basename "$pid_dir"))"
                        break
                    fi
                fi
            done
        done
    fi
    
    # Environment variable leaks
    section "Environment Variables (accessible processes)"
    for pid_dir in /proc/[0-9]*/environ; do
        if [ -r "$pid_dir" ]; then
            env_content=$(tr '\0' '\n' < "$pid_dir" 2>/dev/null | grep -iE 'PASS|SECRET|TOKEN|KEY|API' | head -5)
            if [ -n "$env_content" ]; then
                pid=$(echo "$pid_dir" | cut -d'/' -f3)
                warn "PID $pid has sensitive env vars"
                echo "$env_content" | while read -r line; do
                    info "  $line"
                done
            fi
        fi
    done
    
    # Network connections
    enumerate_network
}

enumerate_network() {
    section "Network Services"
    
    if has_cmd ss; then
        info "Listening services (ss):"
        ss -tlnp 2>/dev/null || ss -tln
    elif has_cmd netstat; then
        info "Listening services (netstat):"
        netstat -tlnp 2>/dev/null || netstat -tln
    elif [ -r /proc/net/tcp ]; then
        info "Listening services (/proc/net/tcp):"
        awk 'NR>1 && $4=="0A" {print "Port: " strtonum("0x" substr($2,index($2,":")+1,4))}' /proc/net/tcp
    fi
    
    # Check for Docker socket
    if [ -S /var/run/docker.sock ]; then
        warn "Docker socket exists: /var/run/docker.sock"
        if [ -w /var/run/docker.sock ]; then
            warn "Docker socket is WRITABLE!"
        fi
    fi
}

# ============================================================================
# FILESYSTEM TRUST BOUNDARIES
# ============================================================================

enumerate_filesystem() {
    section "Filesystem Trust Boundaries"
    
    # Current directory
    info "Current directory: $(pwd)"
    info "$(safe_stat "$(pwd)")"
    
    # PATH analysis
    if [ -n "$PATH" ]; then
        info "PATH: $PATH"
        echo "$PATH" | tr ':' '\n' | while read -r dir; do
            if [ -d "$dir" ] && [ -w "$dir" ]; then
                warn "Writable PATH directory: $dir"
            fi
        done
    fi
    
    # Mount options
    if has_cmd mount; then
        info "Critical mount options:"
        mount | grep -E 'nosuid|nodev|noexec|rw' | while read -r line; do
            info "$line"
        done
    elif [ -r /proc/mounts ]; then
        info "Mounts from /proc/mounts:"
        grep -E 'nosuid|nodev|noexec' /proc/mounts | head -10
    fi
    
    # World-writable directories
    section "World-Writable Directories (common locations)"
    for dir in /tmp /var/tmp /dev/shm; do
        if [ -d "$dir" ]; then
            info "$dir: $(safe_stat "$dir")"
            if [ -w "$dir" ]; then
                warn "  Writable by current user"
            fi
        fi
    done
    
    # Cron directories
    section "Scheduled Tasks"
    for cron_dir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /var/spool/cron; do
        if [ -d "$cron_dir" ]; then
            info "$cron_dir: $(safe_stat "$cron_dir")"
            if [ -w "$cron_dir" ]; then
                warn "  WRITABLE!"
            fi
        fi
    done
    
    # Systemd timers
    if has_cmd systemctl; then
        info "Systemd timers:"
        systemctl list-timers --no-pager 2>/dev/null | head -10
    fi
}

# ============================================================================
# CONTAINER / VM / CI DETECTION
# ============================================================================

enumerate_environment() {
    section "Environment Detection"
    
    # Container detection
    is_container=0
    
    # Check cgroups
    if [ -r /proc/1/cgroup ]; then
        if grep -qE 'docker|lxc|kubepods' /proc/1/cgroup; then
            warn "Container detected (cgroup)"
            is_container=1
        fi
    fi
    
    # Check for .dockerenv
    if [ -f /.dockerenv ]; then
        warn "Docker container detected (.dockerenv)"
        is_container=1
    fi
    
    # Check overlayfs
    if [ -r /proc/mounts ]; then
        if grep -q overlay /proc/mounts; then
            info "OverlayFS detected"
            is_container=1
        fi
    fi
    
    # Kubernetes detection
    if [ -d /run/secrets/kubernetes.io ]; then
        warn "Kubernetes pod detected"
        is_container=1
    fi
    
    if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
        warn "Kubernetes environment variables present"
        is_container=1
    fi
    
    # CI/CD detection
    if [ -n "$CI" ] || [ -n "$GITLAB_CI" ] || [ -n "$GITHUB_ACTIONS" ] || [ -n "$JENKINS_URL" ]; then
        warn "CI/CD environment detected"
        info "CI variables: CI=$CI GITLAB_CI=$GITLAB_CI GITHUB_ACTIONS=$GITHUB_ACTIONS"
    fi
    
    # Cloud detection
    if [ -d /run/cloud-init ]; then
        info "Cloud-init artifacts found"
    fi
    
    # Hostname entropy
    hostname=$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)
    if [ -n "$hostname" ]; then
        info "Hostname: $hostname"
        # Low entropy hostnames (like random hex) suggest containers
        if echo "$hostname" | grep -qE '^[a-f0-9]{12}$'; then
            info "Low-entropy hostname (likely container)"
        fi
    fi
    
    # VM detection
    if [ -r /sys/class/dmi/id/product_name ]; then
        product=$(cat /sys/class/dmi/id/product_name)
        case "$product" in
            *VirtualBox*|*VMware*|*KVM*|*QEMU*)
                info "Virtual machine detected: $product"
                ;;
        esac
    fi
}

# ============================================================================
# SYSTEM INFORMATION
# ============================================================================

enumerate_system() {
    section "System Information"
    
    # Kernel version
    if [ -r /proc/version ]; then
        info "Kernel: $(cat /proc/version)"
    elif has_cmd uname; then
        info "Kernel: $(uname -a)"
    fi
    
    # OS release
    if [ -r /etc/os-release ]; then
        info "OS Release:"
        grep -E '^(NAME|VERSION|ID)=' /etc/os-release | while read -r line; do
            info "  $line"
        done
    fi
    
    # Uptime
    if [ -r /proc/uptime ]; then
        uptime_sec=$(cut -d. -f1 /proc/uptime)
        info "Uptime: $uptime_sec seconds"
    fi
    
    # Architecture
    if has_cmd uname; then
        info "Architecture: $(uname -m)"
    fi
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

main() {
    # Initialize output mode
    init_output
    
    # Header
    buf_append "$(printf "\n")"
    buf_append "$(printf "╔════════════════════════════════════════╗\n")"
    buf_append "$(printf "║  LORE v%s                             ║\n" "$LORE_VERSION")"
    buf_append "$(printf "║  Living-Off-Restricted-Environment     ║\n")"
    buf_append "$(printf "║  Enumerator                            ║\n")"
    buf_append "$(printf "╚════════════════════════════════════════╝\n")"
    
    LORE_START_TIME=$(date 2>/dev/null || echo "unknown")
    
    # Execute enumeration modules
    discover_capabilities
    enumerate_system
    enumerate_environment
    enumerate_identity
    enumerate_processes
    enumerate_filesystem
    
    # Footer
    section "Enumeration Complete"
    info "Started: $LORE_START_TIME"
    info "Finished: $(date 2>/dev/null || echo "unknown")"
    
    buf_append "$(printf "\n")"
    info "Tip: Set LORE_BASE64=1 for base64 encoded output"
    info "Tip: Set LORE_HEX=1 for hex encoded output"
    
    # Flush buffer with encoding if needed
    flush_output
}

# Run main function
main
