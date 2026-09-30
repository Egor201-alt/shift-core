#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_VERSION="1.0.0"
SHIFT_REPO="${SHIFT_REPO:-Egor201-alt/shift-core}"
SHIFT_RELEASE="${SHIFT_RELEASE:-latest}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/shift"
ENV_FILE="$CONFIG_DIR/server.env"
UNIT_FILE="/etc/systemd/system/shift-server.service"
SERVICE_USER="shift"
BIN_NAME="shift-server"
WORK_DIR=""

MODE=""
LISTEN_PORT=""
FORWARD_ADDR=""
FALLBACK_ADDR=""
PSK=""
SERVER_SECRET=""
CAMOUFLAGE="ask"
CAMOUFLAGE_SNI=""
CAMOUFLAGE_PORT="443"
HANDSHAKE_TIMEOUT_MS="4000"
FALLBACK_DRAIN_MS="1500"
NON_INTERACTIVE="false"
UNINSTALL="false"
PURGE="false"
SKIP_FIREWALL="false"

IS_TTY="false"
if [ -t 1 ]; then
    IS_TTY="true"
fi

color() {
    if [ "$IS_TTY" = "true" ]; then
        printf '\033[%sm' "$1"
    fi
}
reset_color() {
    if [ "$IS_TTY" = "true" ]; then
        printf '\033[0m'
    fi
}

log_info() {
    printf '%s[INFO]%s %s\n' "$(color 36)" "$(reset_color)" "$1"
}
log_ok() {
    printf '%s[ OK ]%s %s\n' "$(color 32)" "$(reset_color)" "$1"
}
log_warn() {
    printf '%s[WARN]%s %s\n' "$(color 33)" "$(reset_color)" "$1" >&2
}
log_error() {
    printf '%s[FAIL]%s %s\n' "$(color 31)" "$(reset_color)" "$1" >&2
}

die() {
    log_error "$1"
    exit "${2:-1}"
}

on_error() {
    local exit_code=$?
    local line_no=$1
    log_error "Installer stopped at line $line_no (exit code $exit_code)."
    log_error "Nothing after that point was applied. Re-run with the same flags once the issue above is fixed."
    exit "$exit_code"
}
trap 'on_error $LINENO' ERR

cleanup() {
    if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup EXIT

print_usage() {
    cat <<'USAGE'
Shift Core server installer

Usage:
  install.sh [options]

Modes:
  --mode standalone         Run shift-server on its own, forwarding decrypted
                             traffic to a proxy you already run (or will run)
                             on 127.0.0.1.
  --mode marzban            Try to detect a local Marzban/Xray install and
                             pre-fill the forward port from it.

Network options:
  --listen HOST:PORT        Address shift-server listens on (default 0.0.0.0:443)
  --forward HOST:PORT       Local proxy to forward decrypted traffic to
                             (default 127.0.0.1:10001, or auto-detected in
                             marzban mode)
  --fallback HOST:PORT      Decoy target used when a connection fails to
                             authenticate and camouflage is off, or its SNI
                             cannot be read (default 1.1.1.1:443)

Security options:
  --psk TEXT                Pre-shared passphrase. Generated randomly if
                             omitted.
  --server-secret HEX64     64 hex character X25519 secret, keeps the same
                             public key across restarts. Generated randomly
                             if omitted.
  --camouflage               Enable TLS ClientHello camouflage (default)
  --no-camouflage             Disable it
  --camouflage-sni HOST      Real hostname used for the fake ClientHello
                             (default www.cloudflare.com)
  --camouflage-port PORT    Port used to dial a probe's own SNI (default 443)

Other:
  --repo OWNER/NAME          GitHub repo to fetch a prebuilt release from
                             (default: $SHIFT_REPO env var, or your-org/shift-core)
  --release TAG               Release tag to fetch, or "latest" (default)
  --yes, -y                  Do not prompt, use defaults for anything not
                             given on the command line
  --skip-firewall             Do not touch ufw/firewalld
  --uninstall                  Stop and remove the service
  --purge                      With --uninstall, also remove /etc/shift
  --help, -h                  Show this message
  --version                    Show the installer version

Examples:
  sudo ./install.sh
  sudo ./install.sh --mode standalone --listen 0.0.0.0:443 --forward 127.0.0.1:10001 --yes
  sudo ./install.sh --uninstall --purge
USAGE
}

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        die "This installer needs root (it writes to /etc and /usr/local/bin, and binds low ports). Try: sudo bash $0"
    fi
}

require_linux() {
    local kernel
    kernel="$(uname -s)"
    if [ "$kernel" != "Linux" ]; then
        die "This installer only supports Linux. Detected: $kernel"
    fi
}

detect_arch_slug() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)
            echo "linux-x86_64"
            ;;
        aarch64|arm64)
            echo "linux-arm64"
            ;;
        *)
            die "Unsupported CPU architecture: $machine. Shift Core ships prebuilt binaries for x86_64 and aarch64 only; build from source instead."
            ;;
    esac
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

require_cmd() {
    if ! have_cmd "$1"; then
        die "Required command '$1' is not installed. Install it and re-run this script."
    fi
}

is_valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    if [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        return 1
    fi
    return 0
}

port_of_hostport() {
    printf '%s' "${1##*:}"
}

host_of_hostport() {
    printf '%s' "${1%:*}"
}

is_valid_hostport() {
    local value="$1" port
    case "$value" in
        *:*) : ;;
        *) return 1 ;;
    esac
    port="$(port_of_hostport "$value")"
    is_valid_port "$port"
}

require_valid_hostport() {
    local label="$1" value="$2"
    if ! is_valid_hostport "$value"; then
        die "$label must look like host:port or 0.0.0.0:port (got '$value')."
    fi
}

prompt() {
    local message="$1" default_value="$2" answer
    if [ "$NON_INTERACTIVE" = "true" ]; then
        printf '%s' "$default_value"
        return 0
    fi
    if [ -n "$default_value" ]; then
        printf '%s [%s]: ' "$message" "$default_value" >&2
    else
        printf '%s: ' "$message" >&2
    fi
    read -r answer || answer=""
    if [ -z "$answer" ]; then
        printf '%s' "$default_value"
    else
        printf '%s' "$answer"
    fi
}

prompt_yes_no() {
    local message="$1" default_answer="$2" answer
    if [ "$NON_INTERACTIVE" = "true" ]; then
        [ "$default_answer" = "y" ]
        return $?
    fi
    while true; do
        if [ "$default_answer" = "y" ]; then
            printf '%s [Y/n]: ' "$message" >&2
        else
            printf '%s [y/N]: ' "$message" >&2
        fi
        read -r answer || answer=""
        if [ -z "$answer" ]; then
            answer="$default_answer"
        fi
        case "$answer" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) log_warn "Please answer y or n." ;;
        esac
    done
}

random_hex() {
    local bytes="$1"
    if have_cmd openssl; then
        openssl rand -hex "$bytes"
        return 0
    fi
    if [ -r /dev/urandom ]; then
        head -c "$bytes" /dev/urandom | od -An -tx1 | tr -d ' \n'
        return 0
    fi
    die "Neither openssl nor /dev/urandom is available to generate secrets."
}

detect_public_ip() {
    local ip=""
    if have_cmd curl; then
        ip="$(curl -fsS --max-time 3 https://api.ipify.org 2>/dev/null || true)"
    fi
    if [ -z "$ip" ] && have_cmd ip; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"
    fi
    if [ -z "$ip" ]; then
        ip="<your-server-ip>"
    fi
    printf '%s' "$ip"
}

detect_marzban_forward_port() {
    local port=""
    if have_cmd docker; then
        port="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null \
            | grep -Ei 'xray|marzban-node|marzban' \
            | grep -Eo '127\.0\.0\.1:[0-9]+' \
            | head -n1 \
            | cut -d: -f2 || true)"
    fi
    if [ -z "$port" ] && have_cmd ss; then
        port="$(ss -tlnp 2>/dev/null | grep -i xray | grep -Eo '127\.0\.0\.1:[0-9]+' | head -n1 | cut -d: -f2 || true)"
    fi
    printf '%s' "$port"
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --mode) MODE="$2"; shift 2 ;;
            --listen) LISTEN_PORT="$2"; shift 2 ;;
            --forward) FORWARD_ADDR="$2"; shift 2 ;;
            --fallback) FALLBACK_ADDR="$2"; shift 2 ;;
            --psk) PSK="$2"; shift 2 ;;
            --server-secret) SERVER_SECRET="$2"; shift 2 ;;
            --camouflage) CAMOUFLAGE="true"; shift 1 ;;
            --no-camouflage) CAMOUFLAGE="false"; shift 1 ;;
            --camouflage-sni) CAMOUFLAGE_SNI="$2"; shift 2 ;;
            --camouflage-port) CAMOUFLAGE_PORT="$2"; shift 2 ;;
            --repo) SHIFT_REPO="$2"; shift 2 ;;
            --release) SHIFT_RELEASE="$2"; shift 2 ;;
            --yes|-y) NON_INTERACTIVE="true"; shift 1 ;;
            --skip-firewall) SKIP_FIREWALL="true"; shift 1 ;;
            --uninstall) UNINSTALL="true"; shift 1 ;;
            --purge) PURGE="true"; shift 1 ;;
            --help|-h) print_usage; exit 0 ;;
            --version) printf 'shift-core installer %s\n' "$SCRIPT_VERSION"; exit 0 ;;
            *) die "Unknown option: $1. Run with --help for usage." ;;
        esac
    done
}

check_existing_install() {
    if [ -f "$UNIT_FILE" ]; then
        log_warn "shift-server already appears to be installed ($UNIT_FILE exists)."
        if [ "$NON_INTERACTIVE" = "true" ]; then
            log_warn "Continuing and overwriting the existing configuration (--yes was given)."
            return 0
        fi
        if ! prompt_yes_no "Reconfigure and overwrite the existing install?" "n"; then
            die "Aborted, nothing was changed." 0
        fi
        systemctl stop shift-server 2>/dev/null || true
    fi
}

run_uninstall() {
    require_root
    log_info "Stopping and disabling shift-server..."
    systemctl stop shift-server 2>/dev/null || true
    systemctl disable shift-server 2>/dev/null || true
    rm -f "$UNIT_FILE"
    systemctl daemon-reload
    rm -f "$INSTALL_DIR/$BIN_NAME"
    log_ok "Service and binary removed."
    if [ "$PURGE" = "true" ]; then
        rm -rf "$CONFIG_DIR"
        log_ok "Removed $CONFIG_DIR."
    else
        log_info "Kept $CONFIG_DIR (PSK, server secret). Re-run with --purge to remove it too."
    fi
    exit 0
}

choose_mode() {
    if [ -z "$MODE" ]; then
        if [ "$NON_INTERACTIVE" = "true" ]; then
            MODE="standalone"
        else
            printf '\nHow will shift-server be used?\n' >&2
            printf '  1) standalone, forward to a proxy you run yourself\n' >&2
            printf '  2) with a Marzban/Xray panel already installed on this host\n' >&2
            local choice
            choice="$(prompt "Choose 1 or 2" "1")"
            case "$choice" in
                2) MODE="marzban" ;;
                *) MODE="standalone" ;;
            esac
        fi
    fi
    case "$MODE" in
        standalone|marzban) : ;;
        *) die "--mode must be 'standalone' or 'marzban' (got '$MODE')." ;;
    esac
    log_info "Mode: $MODE"
}

collect_network_settings() {
    local default_listen="0.0.0.0:443"
    if [ -z "$LISTEN_PORT" ]; then
        LISTEN_PORT="$(prompt "Address to listen on" "$default_listen")"
    fi
    require_valid_hostport "--listen" "$LISTEN_PORT"

    if [ -z "$FORWARD_ADDR" ]; then
        local default_forward="127.0.0.1:10001"
        if [ "$MODE" = "marzban" ]; then
            local detected
            detected="$(detect_marzban_forward_port)"
            if [ -n "$detected" ]; then
                default_forward="127.0.0.1:$detected"
                log_ok "Detected a local Xray instance on port $detected."
            else
                log_warn "Could not auto-detect a local Xray/Marzban port, falling back to $default_forward."
                log_warn "Set it up as a new inbound in Marzban listening on 127.0.0.1, then point shift-server at it with --forward."
            fi
        fi
        FORWARD_ADDR="$(prompt "Local address to forward decrypted traffic to" "$default_forward")"
    fi
    require_valid_hostport "--forward" "$FORWARD_ADDR"

    if [ -z "$FALLBACK_ADDR" ]; then
        FALLBACK_ADDR="$(prompt "Decoy fallback target" "1.1.1.1:443")"
    fi
    require_valid_hostport "--fallback" "$FALLBACK_ADDR"

    if [ "$(port_of_hostport "$LISTEN_PORT")" = "$(port_of_hostport "$FORWARD_ADDR")" ] \
        && [ "$(host_of_hostport "$FORWARD_ADDR")" = "127.0.0.1" ]; then
        die "--listen and --forward use the same port ($(port_of_hostport "$LISTEN_PORT")). They must be different."
    fi
}

collect_camouflage_settings() {
    if [ "$CAMOUFLAGE" = "ask" ]; then
        if prompt_yes_no "Enable TLS ClientHello camouflage" "y"; then
            CAMOUFLAGE="true"
        else
            CAMOUFLAGE="false"
        fi
    fi
    if [ "$CAMOUFLAGE" = "true" ]; then
        if [ -z "$CAMOUFLAGE_SNI" ]; then
            CAMOUFLAGE_SNI="$(prompt "Real hostname to imitate in the ClientHello" "www.cloudflare.com")"
        fi
        if [ -z "$CAMOUFLAGE_SNI" ]; then
            die "--camouflage-sni cannot be empty when camouflage is enabled."
        fi
        if ! is_valid_port "$CAMOUFLAGE_PORT"; then
            die "--camouflage-port must be a number between 1 and 65535 (got '$CAMOUFLAGE_PORT')."
        fi
    fi
    log_info "Camouflage: $CAMOUFLAGE"
}

collect_secrets() {
    if [ -z "$PSK" ]; then
        if [ "$NON_INTERACTIVE" = "true" ]; then
            PSK="$(random_hex 32)"
            log_info "Generated a random PSK (shown in the summary at the end)."
        else
            PSK="$(prompt "Shared passphrase (leave empty to generate one)" "")"
            if [ -z "$PSK" ]; then
                PSK="$(random_hex 32)"
            fi
        fi
    fi
    if [ "${#PSK}" -lt 16 ]; then
        log_warn "That PSK is shorter than 16 characters. Consider using a longer one."
    fi

    if [ -z "$SERVER_SECRET" ]; then
        SERVER_SECRET="$(random_hex 32)"
    fi
    if ! printf '%s' "$SERVER_SECRET" | grep -Eq '^[0-9a-fA-F]{64}$'; then
        die "--server-secret must be exactly 64 hex characters (got ${#SERVER_SECRET})."
    fi
}

fetch_prebuilt_binary() {
    local arch_slug url dest_zip
    arch_slug="$(detect_arch_slug)"
    if [ "$SHIFT_RELEASE" = "latest" ]; then
        url="https://github.com/$SHIFT_REPO/releases/latest/download/shift-core-all-platforms.zip"
    else
        url="https://github.com/$SHIFT_REPO/releases/download/$SHIFT_RELEASE/shift-core-all-platforms.zip"
    fi
    dest_zip="$WORK_DIR/shift-core-all-platforms.zip"

    log_info "Looking for a prebuilt binary at $url"
    if ! curl -fsSL --max-time 20 -o "$dest_zip" "$url" 2>/dev/null; then
        log_warn "No prebuilt release found (or network/GitHub unreachable). Will build from source instead."
        return 1
    fi
    if ! have_cmd unzip; then
        log_warn "unzip is not installed, cannot use the prebuilt release. Will build from source instead."
        return 1
    fi
    unzip -q "$dest_zip" -d "$WORK_DIR/dist"
    if [ ! -f "$WORK_DIR/dist/$arch_slug/$BIN_NAME" ]; then
        log_warn "Release archive did not contain a $arch_slug/$BIN_NAME binary. Will build from source instead."
        return 1
    fi
    install -m 755 "$WORK_DIR/dist/$arch_slug/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
    log_ok "Installed prebuilt $BIN_NAME ($arch_slug) to $INSTALL_DIR."
    return 0
}

build_from_source() {
    log_info "Building $BIN_NAME from source. This can take a few minutes."

    if ! have_cmd cargo; then
        log_warn "cargo was not found."
        if [ "$NON_INTERACTIVE" = "true" ] || prompt_yes_no "Install the Rust toolchain now (via rustup)?" "y"; then
            require_cmd curl
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
            # shellcheck disable=SC1090
            . "$HOME/.cargo/env"
        else
            die "cargo is required to build from source. Install Rust and re-run."
        fi
    fi
    require_cmd cargo

    local src_dir
    if [ -f "$(dirname "$0")/../Cargo.toml" ]; then
        src_dir="$(cd "$(dirname "$0")/.." && pwd)"
        log_info "Building from the local checkout at $src_dir."
    else
        require_cmd git
        src_dir="$WORK_DIR/src"
        log_info "Cloning https://github.com/$SHIFT_REPO ..."
        git clone --depth 1 "https://github.com/$SHIFT_REPO.git" "$src_dir"
    fi

    ( cd "$src_dir" && cargo build --release -p shift-server )
    install -m 755 "$src_dir/target/release/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
    log_ok "Built and installed $BIN_NAME to $INSTALL_DIR."
}

install_binary() {
    WORK_DIR="$(mktemp -d)"
    if fetch_prebuilt_binary; then
        return 0
    fi
    build_from_source
}

create_service_user() {
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        return 0
    fi
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
    log_ok "Created system user '$SERVICE_USER'."
}

write_env_file() {
    mkdir -p "$CONFIG_DIR"
    umask 077
    cat > "$ENV_FILE" <<EOF
SHIFT_LISTEN=$LISTEN_PORT
SHIFT_FORWARD=$FORWARD_ADDR
SHIFT_FALLBACK=$FALLBACK_ADDR
SHIFT_PSK=$PSK
SHIFT_SERVER_SECRET=$SERVER_SECRET
SHIFT_HANDSHAKE_TIMEOUT_MS=$HANDSHAKE_TIMEOUT_MS
SHIFT_FALLBACK_DRAIN_MS=$FALLBACK_DRAIN_MS
SHIFT_CAMOUFLAGE=$CAMOUFLAGE
SHIFT_CAMOUFLAGE_PORT=$CAMOUFLAGE_PORT
RUST_LOG=shift_server=info,shift_proto=info
EOF
    if [ "$CAMOUFLAGE" = "true" ]; then
        echo "SHIFT_CAMOUFLAGE_SNI=$CAMOUFLAGE_SNI" >> "$ENV_FILE"
    fi
    chown "$SERVICE_USER:$SERVICE_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    log_ok "Wrote $ENV_FILE."
}

write_systemd_unit() {
    cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Shift Core server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$ENV_FILE
ExecStart=$INSTALL_DIR/$BIN_NAME
Restart=on-failure
RestartSec=2
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    log_ok "Wrote $UNIT_FILE."
}

start_service() {
    systemctl daemon-reload
    systemctl enable --now shift-server
    local tries=0
    while [ "$tries" -lt 20 ]; do
        if systemctl is-active --quiet shift-server; then
            break
        fi
        sleep 0.5
        tries=$((tries + 1))
    done
    if ! systemctl is-active --quiet shift-server; then
        log_error "shift-server did not start. Recent logs:"
        journalctl -u shift-server -n 40 --no-pager || true
        die "Installation failed: the service is not running. Fix the issue above, then run: systemctl restart shift-server"
    fi
    log_ok "shift-server is running."
}

extract_public_key() {
    local tries=0 line=""
    while [ "$tries" -lt 20 ]; do
        line="$(journalctl -u shift-server --no-pager -n 50 2>/dev/null | grep -o 'public_key=[0-9a-f]\{64\}' | tail -n1 || true)"
        if [ -n "$line" ]; then
            printf '%s' "${line#public_key=}"
            return 0
        fi
        sleep 0.3
        tries=$((tries + 1))
    done
    printf ''
}

configure_firewall() {
    if [ "$SKIP_FIREWALL" = "true" ]; then
        return 0
    fi
    local port
    port="$(port_of_hostport "$LISTEN_PORT")"
    if have_cmd ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$port"/tcp >/dev/null 2>&1 || true
        log_ok "Opened $port/tcp in ufw."
    elif have_cmd firewall-cmd && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1 || true
        firewall-cmd --reload >/dev/null 2>&1 || true
        log_ok "Opened $port/tcp in firewalld."
    else
        log_info "No active ufw/firewalld detected. Make sure port $port/tcp is reachable from the internet."
    fi
}

print_summary() {
    local public_key ip listen_port
    public_key="$(extract_public_key)"
    ip="$(detect_public_ip)"
    listen_port="$(port_of_hostport "$LISTEN_PORT")"

    printf '\n'
    printf '%s================  shift-server is up  ================%s\n' "$(color 32)" "$(reset_color)"
    printf 'Server address     %s:%s\n' "$ip" "$listen_port"
    if [ -n "$public_key" ]; then
        printf 'Server public key  %s\n' "$public_key"
    else
        printf 'Server public key  (not found in logs yet, run: journalctl -u shift-server -n 50)\n'
    fi
    printf 'PSK                %s\n' "$PSK"
    printf 'Forward target     %s\n' "$FORWARD_ADDR"
    printf 'Fallback target    %s\n' "$FALLBACK_ADDR"
    printf 'Camouflage         %s' "$CAMOUFLAGE"
    if [ "$CAMOUFLAGE" = "true" ]; then
        printf ' (sni=%s, port=%s)' "$CAMOUFLAGE_SNI" "$CAMOUFLAGE_PORT"
    fi
    printf '\n\n'
    printf 'Client command:\n'
    if [ "$CAMOUFLAGE" = "true" ] && [ -n "$public_key" ]; then
        printf '  shift-cli --server %s:%s --server-public-key %s \\\n' "$ip" "$listen_port" "$public_key"
        printf '    --psk "%s" --camouflage-sni %s --socks-bind 127.0.0.1:1080\n' "$PSK" "$CAMOUFLAGE_SNI"
    elif [ -n "$public_key" ]; then
        printf '  shift-cli --server %s:%s --server-public-key %s \\\n' "$ip" "$listen_port" "$public_key"
        printf '    --psk "%s" --socks-bind 127.0.0.1:1080\n' "$PSK"
    fi
    printf '\n'
    printf 'Config file        %s\n' "$ENV_FILE"
    printf 'Logs               journalctl -u shift-server -f\n'
    printf 'Uninstall          sudo %s --uninstall\n' "$0"
    printf '%s========================================================%s\n' "$(color 32)" "$(reset_color)"
}

main() {
    parse_args "$@"
    require_linux

    if [ "$UNINSTALL" = "true" ]; then
        run_uninstall
    fi

    require_root
    check_existing_install
    choose_mode
    collect_network_settings
    collect_camouflage_settings
    collect_secrets

    install_binary
    create_service_user
    write_env_file
    write_systemd_unit
    start_service
    configure_firewall
    print_summary
}

main "$@"
