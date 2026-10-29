#!/usr/bin/env bash
# ============================================================
#  OpenVPN Manager v4.5
#  - whiptail GUI, user expiry, DNS/port presets
#  - whiptail bootstrap (works on fresh minimal systems)
#  - dedicated OVPN-BAN chain (bans survive firewall restart)
#  - IPv4 + IPv6 abuse bans
#  - rigorous input validation & whitespace stripping
#  - global error trap with line + command context
#  - client isolation (no client-to-client, no duplicate-cn)
#  - RFC1918 / metadata / loopback pivot blocks
#  - hashlimit SYN + new-conn flood protection
#  - abuse monitor with optional auto-ban (CN-based)
#  - forensic JSON audit log (client-connect / disconnect / reject)
#  - TLS reneg-sec 3600, remote-cert-tls client
#  Inspiration: Nyr/openvpn-install (MIT)
# ============================================================
set -Eeuo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ---------- Paths & identifiers (early for trap) ----------
LOG=/var/log/ovpn-manager.log
TITLE="OpenVPN Manager"

# ---------- Global error trap ----------
_on_error() {
  local code=$? line=$1 cmd=$2
  set +e
  [[ $code -eq 0 ]] && exit 0
  printf '[%s] FATAL exit=%s line=%s cmd=%s\n' \
    "$(date '+%F %T')" "$code" "$line" "$cmd" >> "$LOG" 2>/dev/null || true
  if command -v whiptail >/dev/null 2>&1; then
    whiptail --title "$TITLE" --msgbox \
      "An unexpected error occurred.\n\nExit code: $code\nLine: $line\n\nSee $LOG for details." \
      14 74 2>/dev/null || true
  else
    echo "FATAL: exit $code at line $line. See $LOG" >&2
  fi
  exit $code
}
trap '_on_error $LINENO "$BASH_COMMAND"' ERR

# ---------- Environment sanity ----------
if readlink /proc/$$/exe 2>/dev/null | grep -q dash; then
  echo 'Run with "bash", not "sh".' >&2; exit 1
fi
[[ $EUID -eq 0 ]] || { echo "Run as root (sudo)." >&2; exit 1; }
grep -q sbin <<< "$PATH" || { echo '$PATH missing sbin; use "su -".' >&2; exit 1; }
if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
  echo "TUN device unavailable. Enable TUN before running." >&2; exit 1
fi
exec 7<&- 2>/dev/null || true
read -N 999999 -t 0.001 2>/dev/null || true

# ---------- Paths ----------
OVPN_DIR=/etc/openvpn/server
EASYRSA_DIR=$OVPN_DIR/easy-rsa
CLIENT_DIR=/etc/openvpn/clients
EXPIRY_DIR=/etc/openvpn/expiry
BAN_DIR=/etc/openvpn/banned
AUDIT_DIR=/var/log/ovpn
AUDIT_LOG=$AUDIT_DIR/audit.jsonl
ABUSE_CFG=/etc/openvpn/abuse.conf
SERVER_CONF=$OVPN_DIR/server.conf
COMMON_CONF=$OVPN_DIR/client-common.txt
HOOK=$OVPN_DIR/client-connect.sh
HOOK_DISC=$OVPN_DIR/client-disconnect.sh
STATE_FILE=/etc/openvpn/state.conf
ENDPOINT_FILE=/etc/openvpn/endpoint
EXPIRY_SCRIPT=/usr/local/sbin/ovpn-expiry-check
ABUSE_SCRIPT=/usr/local/sbin/ovpn-abuse-monitor.sh
BAN_SYNC_SCRIPT=/usr/local/sbin/ovpn-ban-sync.sh
IPT_SERVICE=/etc/systemd/system/openvpn-iptables.service

VPN_NET=10.8.0.0
VPN_MASK=255.255.255.0
VPN_CIDR=10.8.0.0/24
VPN6_CIDR=fddd:1194:1194:1194::/64
EASYRSA_VER=3.2.7

# ---------- State ----------
DNS1=1.1.1.1
DNS2=1.0.0.1
PROTO=udp
PORT=1194
ENDPOINT=""
IPv6_ENABLED=0
SERVER_IP4=""
SERVER_IP6=""
BLOCK_DNS=1
GRP=nogroup
OS=""

# ---------- Utilities ----------
log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG" >&2; }
die(){ log "ERROR: $*"; whiptail --title "$TITLE" --msgbox "ERROR:\n$*" 15 70 2>/dev/null || true; exit 1; }
msg(){ whiptail --title "$TITLE" --msgbox "$1" 16 74 3>&1 1>&2 2>&3 || true; }
yesno(){ whiptail --title "$TITLE" --yesno "$1" 12 74 3>&1 1>&2 2>&3; }
input(){ whiptail --title "$TITLE" --inputbox "$1" 10 74 "${2:-}" 3>&1 1>&2 2>&3; }
is_installed(){ [[ -f $SERVER_CONF && -f $EASYRSA_DIR/pki/ca.crt ]]; }

# Ensure whiptail exists before we ever try to use the GUI.
bootstrap_whiptail(){
  command -v whiptail >/dev/null 2>&1 && return 0
  echo "Installing whiptail (newt) ..." >&2
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y --no-install-recommends whiptail >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y newt >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y newt >/dev/null 2>&1 || true
  fi
  command -v whiptail >/dev/null 2>&1 || {
    echo "FATAL: cannot install whiptail. Install 'whiptail' or 'newt' and re-run." >&2
    exit 1
  }
}

is_valid_ipv4(){
  local ip=$1 o octet
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS='.' read -r -a o <<< "$ip"
  for octet in "${o[@]}"; do
    (( 10#$octet <= 255 )) || return 1
  done
  return 0
}

is_valid_endpoint(){
  local ep=$1
  is_valid_ipv4 "$ep" && return 0
  (( ${#ep} <= 253 )) || return 1
  [[ $ep =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

load_state(){
  [[ -f $STATE_FILE ]] || return 0
  # Refuse to source if the state file contains anything that could execute code.
  if grep -qE '[`$(){}|&;]' "$STATE_FILE" 2>/dev/null; then
    log "WARNING: $STATE_FILE contains suspicious content; skipping source."
    return 0
  fi
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  ENDPOINT=$(cat "$ENDPOINT_FILE" 2>/dev/null || echo "")
  if [[ -d $OVPN_DIR ]]; then
    GRP=$(awk '/^group /{print $2;exit}' "$SERVER_CONF" 2>/dev/null || echo "$GRP")
  fi
  return 0
}

save_state(){
  {
    printf 'PROTO=%s\nPORT=%s\nDNS1=%s\nDNS2=%s\n' "$PROTO" "$PORT" "$DNS1" "$DNS2"
    printf 'SERVER_IP4=%s\nSERVER_IP6=%s\nIPv6_ENABLED=%s\nBLOCK_DNS=%s\n' \
      "$SERVER_IP4" "$SERVER_IP6" "$IPv6_ENABLED" "$BLOCK_DNS"
  } > "$STATE_FILE"
  echo "$ENDPOINT" > "$ENDPOINT_FILE"
}

list_user_names(){
  [[ -d $EASYRSA_DIR/pki/issued ]] || return 0
  local f b
  for f in "$EASYRSA_DIR/pki/issued"/*.crt; do
    [[ -e $f ]] || continue
    b=$(basename "$f" .crt)
    [[ $b == server ]] && continue
    echo "$b"
  done
}

# ---------- OS detection ----------
detect_os(){
  if grep -qs "ubuntu" /etc/os-release; then
    OS=ubuntu
    local v
    v=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.') || v=0
    (( v >= 2204 )) || die "Ubuntu 22.04+ required."
    GRP=nogroup
  elif [[ -e /etc/debian_version ]]; then
    grep -q '/sid' /etc/debian_version && die "Debian testing/unstable unsupported."
    OS=debian
    local v
    v=$(grep -oE '[0-9]+' /etc/debian_version | head -1) || v=0
    (( v >= 11 )) || die "Debian 11+ required."
    GRP=nogroup
  elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
    OS=centos
    local v
    v=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1) || v=0
    (( v >= 9 )) || die "Alma/Rocky/CentOS 9+ required."
    GRP=nobody
  elif [[ -e /etc/fedora-release ]]; then
    OS=fedora; GRP=nobody
  else
    die "Unsupported distribution."
  fi
}

# ---------- IP pickers (awk-based parsing to avoid regex edge cases) ----------
pick_ipv4(){
  local ips count
  ips=$(ip -4 addr 2>/dev/null | awk '/inet / && !/127\./ {print $2}' | cut -d '/' -f 1 || true)
  count=$(grep -c . <<< "$ips" || true)
  if (( count == 0 )); then die "No non-loopback IPv4 addresses."; fi
  if (( count == 1 )); then SERVER_IP4=$ips; return 0; fi
  local args=() i=1 ip
  while read -r ip; do
    [[ -z $ip ]] && continue
    args+=("$i" "$ip"); i=$((i+1))
  done <<< "$ips"
  local pick
  pick=$(whiptail --title "$TITLE" --menu "Bind OpenVPN to which IPv4?" \
    20 66 10 "${args[@]}" 3>&1 1>&2 2>&3) || die "Cancelled."
  SERVER_IP4=$(sed -n "${pick}p" <<< "$ips")
  return 0
}

pick_ipv6(){
  local ips count
  ips=$(ip -6 addr 2>/dev/null | awk '/inet6 [23]/ {print $2}' | cut -d '/' -f 1 || true)
  count=$(grep -c . <<< "$ips" || true)
  if (( count == 0 )); then SERVER_IP6=""; return 0; fi
  if (( count == 1 )); then SERVER_IP6=$ips; return 0; fi
  local args=() i=1 ip
  while read -r ip; do
    [[ -z $ip ]] && continue
    args+=("$i" "$ip"); i=$((i+1))
  done <<< "$ips"
  local pick
  pick=$(whiptail --title "$TITLE" --menu "Bind OpenVPN to which IPv6?" \
    20 66 10 "${args[@]}" 3>&1 1>&2 2>&3) || { SERVER_IP6=""; return 0; }
  SERVER_IP6=$(sed -n "${pick}p" <<< "$ips")
  return 0
}

# ---------- Pickers ----------
choose_proto(){
  local p
  p=$(whiptail --title "$TITLE" --menu "Protocol:" 12 60 2 \
    "udp" "UDP (recommended, faster)" \
    "tcp" "TCP (firewall-friendly, slower)" 3>&1 1>&2 2>&3) || return 1
  PROTO=$p
  return 0
}

choose_port(){
  local proto=${1:-udp} def choice
  [[ $proto == udp ]] && def=1194 || def=443
  while true; do
    choice=$(whiptail --title "$TITLE" --menu "Port for ${proto^^}:" 20 74 8 \
      "1194"   "1194 - OpenVPN default" \
      "443"    "443  - usually open" \
      "53"     "53   - DNS" \
      "80"     "80   - HTTP" \
      "8080"   "8080 - HTTP-alt" \
      "992"    "992  - OpenVPN alt" \
      "custom" "Custom..." 3>&1 1>&2 2>&3) || return 1
    if [[ $choice == custom ]]; then
      PORT=$(input "Enter custom port (1-65535):" "$def") || return 1
      PORT="${PORT// /}"
    else
      PORT=$choice
    fi
    if [[ $PORT =~ ^[0-9]+$ ]]; then
      local n=$((10#$PORT))
      if (( n >= 1 && n <= 65535 )); then
        PORT=$n
        return 0
      fi
    fi
    msg "Invalid port: '$PORT'. Must be a number between 1 and 65535."
  done
}

choose_dns(){
  while true; do
    local choice
    choice=$(whiptail --title "$TITLE" --menu "DNS pushed to VPN clients:" 22 78 10 \
      "cloudflare" "Cloudflare  (1.1.1.1, 1.0.0.1)" \
      "google"     "Google      (8.8.8.8, 8.8.4.4)" \
      "quad9"      "Quad9       (9.9.9.9, 149.112.112.112)" \
      "opendns"    "OpenDNS     (208.67.222.222, 208.67.220.220)" \
      "gcore"      "Gcore       (95.85.95.85, 2.56.220.2)" \
      "adguard"    "AdGuard     (94.140.14.14, 94.140.15.15)" \
      "nextdns"    "NextDNS     (45.90.28.0, 45.90.30.0)" \
      "system"     "Host resolv.conf servers" \
      "custom"     "Custom..." 3>&1 1>&2 2>&3) || return 1
    case $choice in
      cloudflare) DNS1=1.1.1.1;        DNS2=1.0.0.1; return 0 ;;
      google)     DNS1=8.8.8.8;        DNS2=8.8.4.4; return 0 ;;
      quad9)      DNS1=9.9.9.9;        DNS2=149.112.112.112; return 0 ;;
      opendns)    DNS1=208.67.222.222; DNS2=208.67.220.220; return 0 ;;
      gcore)      DNS1=95.85.95.85;    DNS2=2.56.220.2; return 0 ;;
      adguard)    DNS1=94.140.14.14;   DNS2=94.140.15.15; return 0 ;;
      nextdns)    DNS1=45.90.28.0;     DNS2=45.90.30.0; return 0 ;;
      system)
        local rc=/etc/resolv.conf
        if grep -q '127.0.0.53' "$rc" 2>/dev/null; then
          rc=/run/systemd/resolve/resolv.conf
        fi
        local srv
        srv=$(grep '^nameserver' "$rc" 2>/dev/null \
              | grep -v '127.0.0.53' \
              | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' \
              | head -2 | paste -sd' ' - || true)
        DNS1=$(awk '{print $1}' <<< "$srv")
        DNS2=$(awk '{print $2}' <<< "$srv")
        [[ -n $DNS1 ]] && return 0
        msg "Cannot read resolv.conf automatically. Try custom."
        ;;
      custom)
        local d1 d2
        d1=$(input "Primary DNS (IPv4 required):" "$DNS1") || continue
        d1="${d1// /}"
        if ! is_valid_ipv4 "$d1"; then
          msg "Invalid IPv4 for Primary DNS: '$d1'"
          continue
        fi
        d2=$(input "Secondary DNS (IPv4, blank for none):" "$DNS2") || continue
        d2="${d2// /}"
        if [[ -n $d2 ]] && ! is_valid_ipv4 "$d2"; then
          msg "Invalid IPv4 for Secondary DNS: '$d2'"
          continue
        fi
        DNS1=$d1; DNS2=$d2; return 0
        ;;
    esac
  done
}

# ---------- Deps / easy-rsa ----------
install_deps(){
  detect_os
  log "Installing dependencies for $OS..."
  if [[ $OS == ubuntu || $OS == debian ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends openvpn openssl ca-certificates \
      iptables curl wget whiptail tar jq
  elif [[ $OS == centos ]]; then
    dnf install -y epel-release >/dev/null 2>&1 || true
    dnf install -y openvpn openssl ca-certificates iptables curl wget tar newt jq
  elif [[ $OS == fedora ]]; then
    dnf install -y openvpn openssl ca-certificates iptables curl wget tar newt jq
  fi
}

download_easyrsa(){
  if [[ -x $EASYRSA_DIR/easyrsa ]]; then return 0; fi
  log "Downloading easy-rsa $EASYRSA_VER..."
  mkdir -p "$EASYRSA_DIR"
  local url="https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VER}/EasyRSA-${EASYRSA_VER}.tgz"
  { wget -qO- "$url" 2>/dev/null || curl -sL "$url"; } \
    | tar xz -C "$EASYRSA_DIR" --strip-components 1
  chown -R root:root "$EASYRSA_DIR"
  [[ -x $EASYRSA_DIR/easyrsa ]] || die "Failed to download easy-rsa."
}

easyrsa(){
  ( cd "$EASYRSA_DIR"; EASYRSA_BATCH=1 EASYRSA_CRL_DAYS=3650 ./easyrsa "$@" )
}

# ---------- PKI ----------
setup_pki(){
  download_easyrsa
  mkdir -p "$CLIENT_DIR" "$EXPIRY_DIR" "$BAN_DIR"
  chmod 755 "$BAN_DIR"

  ( cd "$EASYRSA_DIR"
    [[ -f pki/ca.crt ]]             || ./easyrsa --batch init-pki
    [[ -f pki/ca.crt ]]             || ./easyrsa --batch build-ca nopass
    [[ -f pki/private/server.key ]] || ./easyrsa --batch --days=3650 build-server-full server nopass
    [[ -f pki/crl.pem ]]            || ./easyrsa --batch --days=3650 gen-crl
    [[ -f pki/private/tls.key ]]    || ./easyrsa --batch gen-tls-crypt-key )

  if [[ ! -f $OVPN_DIR/dh.pem ]]; then
    cat > "$OVPN_DIR/dh.pem" <<'DH'
-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
DH
  fi
  ln -sf "$OVPN_DIR/dh.pem" "$EASYRSA_DIR/pki/dh.pem" 2>/dev/null || true

  cp -f "$EASYRSA_DIR/pki/ca.crt"             "$OVPN_DIR/ca.crt"
  cp -f "$EASYRSA_DIR/pki/private/ca.key"     "$OVPN_DIR/ca.key"
  cp -f "$EASYRSA_DIR/pki/issued/server.crt"  "$OVPN_DIR/server.crt"
  cp -f "$EASYRSA_DIR/pki/private/server.key" "$OVPN_DIR/server.key"
  cp -f "$EASYRSA_DIR/pki/crl.pem"            "$OVPN_DIR/crl.pem"
  cp -f "$EASYRSA_DIR/pki/private/tls.key"    "$OVPN_DIR/tc.key"

  chmod 600 "$OVPN_DIR"/*.key
  chmod 644 "$OVPN_DIR/crl.pem" "$OVPN_DIR/ca.crt" "$OVPN_DIR/dh.pem"
  chown nobody:"$GRP" "$OVPN_DIR/crl.pem" 2>/dev/null || true
  chmod o+x "$OVPN_DIR"
}

# ---------- Server config ----------
write_server_conf(){
  local proto=$1 port=$2 dns1=$3 dns2=$4
  local extra="" v6extra="" dns2_line=""
  [[ $proto == udp ]] && extra="explicit-exit-notify 1"
  [[ -n $dns2 ]]      && dns2_line="push \"dhcp-option DNS $dns2\""
  (( IPv6_ENABLED ))  && v6extra="server-ipv6 $VPN6_CIDR"

  local bind4=""; [[ -n $SERVER_IP4 ]] && bind4="local $SERVER_IP4"
  local block_dns_line=""
  (( BLOCK_DNS )) && block_dns_line='push "block-outside-dns"'

  cat > "$SERVER_CONF" <<EOF
$bind4
port $port
proto $proto
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
tls-crypt tc.key
topology subnet
server $VPN_NET $VPN_MASK
$v6extra
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS $dns1"
$dns2_line
$block_dns_line
keepalive 10 120
user nobody
group $GRP
persist-key
persist-tun
verb 3
crl-verify crl.pem

# ---- Hardening ----
# NOTE: client-to-client MUST stay absent (client isolation).
# duplicate-cn MUST stay absent (reuse of client cert rejected).
remote-cert-tls client
tls-version-min 1.2
reneg-sec 3600
reneg-bytes 0
reneg-pkts 0
tran-window 300
max-clients 100

script-security 2
client-connect $HOOK
client-disconnect $HOOK_DISC

status /var/log/openvpn-status.log 30
$extra
EOF
  chmod 600 "$SERVER_CONF"
  sed -i '/^[[:space:]]*duplicate-cn[[:space:]]/d' "$SERVER_CONF"

  cat > "$COMMON_CONF" <<EOF
client
dev tun
proto $proto
remote $ENDPOINT $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
ignore-unknown-option block-outside-dns
verb 3
EOF
}

enable_forwarding(){
  {
    echo 'net.ipv4.ip_forward=1'
    (( IPv6_ENABLED )) && echo 'net.ipv6.conf.all.forwarding=1'
  } > /etc/sysctl.d/99-openvpn-forward.conf
  echo 1 > /proc/sys/net/ipv4/ip_forward
  if (( IPv6_ENABLED )); then
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
  fi
}

container_dropin(){
  if systemd-detect-virt -cq 2>/dev/null; then
    mkdir -p /etc/systemd/system/openvpn-server@server.service.d/
    printf '[Service]\nLimitNPROC=infinity\n' \
      > /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
    systemctl daemon-reload
  fi
}

# ---------- Ban sync helper ----------
install_ban_sync(){
  cat > "$BAN_SYNC_SCRIPT" <<'EOS'
#!/usr/bin/env bash
# Reapply ban rules from /etc/openvpn/banned into the OVPN-BAN chain.
# Invoked by openvpn-iptables.service ExecStartPost (idempotent).
set -u
BAN_DIR=/etc/openvpn/banned
[[ -d $BAN_DIR ]] || exit 0
shopt -s nullglob

ipt=$(command -v iptables 2>/dev/null || true)
ip6t=$(command -v ip6tables 2>/dev/null || true)

for f in "$BAN_DIR"/*; do
  ip=$(cat "$f" 2>/dev/null) || continue
  [[ -z $ip ]] && continue
  if [[ $ip == *:* ]]; then
    [[ -n $ip6t ]] || continue
    $ip6t -w 5 -C OVPN-BAN -s "$ip" -j DROP 2>/dev/null \
      || $ip6t -w 5 -I OVPN-BAN 1 -s "$ip" -j DROP 2>/dev/null || true
  else
    [[ -n $ipt ]] || continue
    $ipt -w 5 -C OVPN-BAN -s "$ip" -j DROP 2>/dev/null \
      || $ipt -w 5 -I OVPN-BAN 1 -s "$ip" -j DROP 2>/dev/null || true
  fi
done
exit 0
EOS
  chmod 755 "$BAN_SYNC_SCRIPT"
}

# ---------- Firewall ----------
apply_firewall_iptables(){
  local proto=$1 port=$2 ipt ip6t
  ipt=$(command -v iptables)   || die "iptables not found"
  ip6t=$(command -v ip6tables 2>/dev/null || true)
  if [[ $(systemd-detect-virt 2>/dev/null) == "openvz" ]] \
     && readlink -f "$ipt" | grep -q nft && hash iptables-legacy 2>/dev/null; then
    ipt=$(command -v iptables-legacy)
    ip6t=$(command -v ip6tables-legacy 2>/dev/null || true)
  fi
  if (( IPv6_ENABLED )); then
    [[ -n $ip6t ]] || die "IPv6 enabled but ip6tables is missing. Install iptables (v6) or disable IPv6 in the VPN."
  fi

  install_ban_sync

  local -a L=()
  # Tear down any old jumps, then rebuild both chains.
  L+=("ExecStart=-$ipt -w 5 -D FORWARD -j OVPN-BAN")
  L+=("ExecStart=-$ipt -w 5 -D FORWARD -j OVPN-FWD")
  L+=("ExecStart=-$ipt -w 5 -N OVPN-BAN")
  L+=("ExecStart=-$ipt -w 5 -N OVPN-FWD")
  L+=("ExecStart=-$ipt -w 5 -F OVPN-BAN")
  L+=("ExecStart=$ipt -w 5 -F OVPN-FWD")
  L+=("ExecStart=$ipt -w 5 -I FORWARD 1 -j OVPN-BAN")
  L+=("ExecStart=$ipt -w 5 -I FORWARD 2 -j OVPN-FWD")

  # Rate limits, pivot blocks and accepts live in OVPN-FWD.
  L+=("ExecStart=$ipt -w 5 -A OVPN-FWD -s $VPN_CIDR -p tcp --syn -m hashlimit --hashlimit-above 100/sec --hashlimit-burst 200 --hashlimit-mode srcip --hashlimit-name ovpn_syn -j DROP")
  L+=("ExecStart=$ipt -w 5 -A OVPN-FWD -s $VPN_CIDR -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 60 --hashlimit-mode srcip --hashlimit-name ovpn_new -j DROP")

  local dst
  for dst in 169.254.169.254/32 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8; do
    L+=("ExecStart=$ipt -w 5 -A OVPN-FWD -s $VPN_CIDR -d $dst -j DROP")
  done

  L+=("ExecStart=$ipt -w 5 -A OVPN-FWD -m state --state RELATED,ESTABLISHED -j ACCEPT")
  L+=("ExecStart=$ipt -w 5 -A OVPN-FWD -s $VPN_CIDR -j ACCEPT")

  L+=("ExecStart=-$ipt -w 5 -t nat -D POSTROUTING -s $VPN_CIDR ! -d $VPN_CIDR -j SNAT --to $SERVER_IP4")
  L+=("ExecStart=$ipt -w 5 -t nat -A POSTROUTING -s $VPN_CIDR ! -d $VPN_CIDR -j SNAT --to $SERVER_IP4")
  L+=("ExecStart=-$ipt -w 5 -D INPUT -p $proto --dport $port -j ACCEPT")
  L+=("ExecStart=$ipt -w 5 -I INPUT -p $proto --dport $port -j ACCEPT")

  # Bans are restored from disk by ExecStartPost.
  L+=("ExecStartPost=$BAN_SYNC_SCRIPT")

  L+=("ExecStop=-$ipt -w 5 -D FORWARD -j OVPN-BAN")
  L+=("ExecStop=-$ipt -w 5 -D FORWARD -j OVPN-FWD")
  L+=("ExecStop=-$ipt -w 5 -F OVPN-BAN")
  L+=("ExecStop=-$ipt -w 5 -X OVPN-BAN")
  L+=("ExecStop=$ipt -w 5 -F OVPN-FWD")
  L+=("ExecStop=-$ipt -w 5 -X OVPN-FWD")
  L+=("ExecStop=-$ipt -w 5 -t nat -D POSTROUTING -s $VPN_CIDR ! -d $VPN_CIDR -j SNAT --to $SERVER_IP4")
  L+=("ExecStop=-$ipt -w 5 -D INPUT -p $proto --dport $port -j ACCEPT")

  if (( IPv6_ENABLED )) && [[ -n $SERVER_IP6 ]]; then
    L+=("ExecStart=-$ip6t -w 5 -N OVPN-BAN")
    L+=("ExecStart=$ip6t -w 5 -A OVPN-FWD -s $VPN6_CIDR -d fc00::/7 -j DROP")
    L+=("ExecStart=$ip6t -w 5 -A OVPN-FWD -s $VPN6_CIDR -d fe80::/10 -j DROP")
    L+=("ExecStart=$ip6t -w 5 -A OVPN-FWD -s $VPN6_CIDR -m state --state RELATED,ESTABLISHED -j ACCEPT")
    L+=("ExecStart=$ip6t -w 5 -A OVPN-FWD -s $VPN6_CIDR -j ACCEPT")
    L+=("ExecStart=-$ip6t -w 5 -t nat -D POSTROUTING -s $VPN6_CIDR ! -d $VPN6_CIDR -j SNAT --to $SERVER_IP6")
    L+=("ExecStart=$ip6t -w 5 -t nat -A POSTROUTING -s $VPN6_CIDR ! -d $VPN6_CIDR -j SNAT --to $SERVER_IP6")
    L+=("ExecStop=-$ip6t -w 5 -t nat -D POSTROUTING -s $VPN6_CIDR ! -d $VPN6_CIDR -j SNAT --to $SERVER_IP6")
  fi

  {
    echo "[Unit]"
    echo "Description=OpenVPN NAT + hardening rules"
    echo "After=network-online.target"
    echo "Wants=network-online.target"
    echo "[Service]"
    echo "Type=oneshot"
    printf '%s\n' "${L[@]}"
    echo "RemainAfterExit=yes"
    echo "[Install]"
    echo "WantedBy=multi-user.target"
  } > "$IPT_SERVICE"

  systemctl daemon-reload
  systemctl enable openvpn-iptables.service >/dev/null 2>&1 || true
  systemctl restart openvpn-iptables.service
}

apply_firewall_firewalld(){
  local proto=$1 port=$2
  firewall-cmd --permanent --add-port="$port/$proto" >/dev/null
  firewall-cmd --permanent --zone=trusted --add-source="$VPN_CIDR" >/dev/null
  firewall-cmd --permanent --add-masquerade >/dev/null

  local dst
  for dst in 169.254.169.254/32 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8; do
    firewall-cmd --permanent --direct --remove-rule ipv4 filter FORWARD 0 \
      -s "$VPN_CIDR" -d "$dst" -j DROP >/dev/null 2>&1 || true
  done

  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 \
    -s "$VPN_CIDR" -p tcp --syn -m hashlimit \
    --hashlimit-above 100/sec --hashlimit-burst 200 \
    --hashlimit-mode srcip --hashlimit-name ovpn_syn -j DROP >/dev/null
  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 \
    -s "$VPN_CIDR" -m conntrack --ctstate NEW -m hashlimit \
    --hashlimit-above 30/sec --hashlimit-burst 60 \
    --hashlimit-mode srcip --hashlimit-name ovpn_new -j DROP >/dev/null

  for dst in 169.254.169.254/32 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8; do
    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 \
      -s "$VPN_CIDR" -d "$dst" -j DROP >/dev/null
  done

  firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 10 \
    -s "$VPN_CIDR" -j ACCEPT >/dev/null

  firewall-cmd --reload >/dev/null

  # Bans still use OVPN-BAN via iptables (works alongside firewalld on both
  # the iptables-nft and iptables-legacy backends).
  install_ban_sync
  local ipt
  ipt=$(command -v iptables) || return 0
  $ipt -w 5 -N OVPN-BAN 2>/dev/null || true
  $ipt -w 5 -C FORWARD -j OVPN-BAN 2>/dev/null \
    || $ipt -w 5 -I FORWARD 1 -j OVPN-BAN 2>/dev/null || true
  "$BAN_SYNC_SCRIPT" >/dev/null 2>&1 || true
}

apply_firewall(){
  local proto=$1 port=$2
  if systemctl is-active --quiet firewalld.service; then
    apply_firewall_firewalld "$proto" "$port"
  else
    apply_firewall_iptables "$proto" "$port"
  fi
}

selinux_port(){
  local proto=$1 port=$2
  if command -v sestatus >/dev/null 2>&1 \
     && sestatus 2>/dev/null | grep "Current mode" | grep -q enforcing \
     && [[ $port != 1194 ]]; then
    hash semanage 2>/dev/null || dnf install -y policycoreutils-python-utils >/dev/null 2>&1 || true
    semanage port -a -t openvpn_port_t -p "$proto" "$port" 2>/dev/null \
      || semanage port -m -t openvpn_port_t -p "$proto" "$port" 2>/dev/null || true
  fi
}

# ---------- Client .ovpn ----------
build_client_config(){
  local name=$1
  mkdir -p "$CLIENT_DIR"
  local out="$CLIENT_DIR/$name.ovpn"
  {
    cat "$COMMON_CONF"
    echo "<ca>";        cat "$OVPN_DIR/ca.crt";                       echo "</ca>"
    echo "<cert>";      awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' \
                         "$EASYRSA_DIR/pki/issued/$name.crt";         echo "</cert>"
    echo "<key>";       cat "$EASYRSA_DIR/pki/private/$name.key";     echo "</key>"
    echo "<tls-crypt>"; cat "$OVPN_DIR/tc.key";                       echo "</tls-crypt>"
  } > "$out"
  chmod 600 "$out"
}

# ---------- Expiry cron ----------
install_expiry_cron(){
  cat > "$EXPIRY_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -euo pipefail
EASYRSA_DIR=/etc/openvpn/server/easy-rsa
EXPIRY_DIR=/etc/openvpn/expiry
CLIENT_DIR=/etc/openvpn/clients
OVPN_DIR=/etc/openvpn/server
GRP=nogroup; getent group nogroup >/dev/null 2>&1 || GRP=nobody
[[ -d $EXPIRY_DIR ]] || exit 0
now=$(date +%s)
for f in "$EXPIRY_DIR"/*; do
  [[ -e $f ]] || continue
  u=$(basename "$f"); exp=$(cat "$f" 2>/dev/null || echo 0)
  [[ $exp =~ ^[0-9]+$ ]] || continue
  if (( now >= exp )); then
    ( cd "$EASYRSA_DIR"
      ./easyrsa --batch revoke "$u" >/dev/null 2>&1 || true
      ./easyrsa --batch --days=3650 gen-crl >/dev/null 2>&1 || true
      cp -f pki/crl.pem "$OVPN_DIR/crl.pem" 2>/dev/null || true
      chmod 644 "$OVPN_DIR/crl.pem" 2>/dev/null || true
      chown nobody:"$GRP" "$OVPN_DIR/crl.pem" 2>/dev/null || true )
    rm -f "$CLIENT_DIR/$u.ovpn" "$f"
    logger -t ovpn-expiry "Revoked expired user: $u" || true
  fi
done
EOS
  chmod 755 "$EXPIRY_SCRIPT"
  echo "*/5 * * * * root $EXPIRY_SCRIPT >/dev/null 2>&1" > /etc/cron.d/ovpn-expiry
  chmod 644 /etc/cron.d/ovpn-expiry
}

# ---------- Abuse monitor ----------
install_abuse_protection(){
  mkdir -p "$BAN_DIR"; chmod 755 "$BAN_DIR"

  cat > "$ABUSE_SCRIPT" <<'EOS'
#!/usr/bin/env bash
set -u
STATUS=/var/log/openvpn-status.log
STATE=/var/lib/ovpn-abuse/prev
BAN=/etc/openvpn/banned
LOG=/var/log/ovpn-abuse.log
CFG=/etc/openvpn/abuse.conf

THRESHOLD_BPS=$(( 50 * 1024 * 1024 ))
AUTO_BAN=0
INTERVAL=60
[[ -f $CFG ]] && source "$CFG"
[[ -f $STATUS ]] || exit 0
mkdir -p "$(dirname "$STATE")" "$BAN"
touch "$LOG"

declare -A prev
if [[ -f $STATE ]]; then
  while IFS=, read -r cn b; do
    [[ -n $cn ]] && prev["$cn"]=$b
  done < "$STATE"
fi

declare -A curr
while IFS=, read -r cn real virt br bs; do
  [[ -z $cn ]] && continue
  total=$(( br + bs ))
  curr["$cn"]=$total
  realip=${real%:*}
  realip=${realip#[}; realip=${realip%]}

  delta=$(( total - ${prev["$cn"]:-$total} ))
  (( delta < 0 )) && delta=0 || true
  rate=$(( delta / INTERVAL ))

  if (( rate > THRESHOLD_BPS )); then
    echo "[$(date '+%F %T')] HIGH_BW cn=$cn rate=${rate}B/s ip=$realip" >> "$LOG"
    if (( AUTO_BAN )) && [[ ! -f "$BAN/$cn" ]]; then
      echo "$virt" > "$BAN/$cn"
      chmod 644 "$BAN/$cn"
      if [[ $virt == *:* ]]; then
        ip6tables -w 5 -I OVPN-BAN 1 -s "$virt" -j DROP 2>/dev/null || true
      else
        iptables  -w 5 -I OVPN-BAN 1 -s "$virt" -j DROP 2>/dev/null || true
      fi
      logger -t ovpn-abuse "Banned $cn for bandwidth abuse (${rate}B/s)"
    fi
  fi
done < <(awk -F',' '/^CLIENT_LIST/ {print $2","$3","$4","$6","$7}' "$STATUS" 2>/dev/null || true)

: > "$STATE"
for cn in "${!curr[@]}"; do echo "$cn,${curr[$cn]}" >> "$STATE"; done
EOS
  chmod 755 "$ABUSE_SCRIPT"

  cat > "$ABUSE_CFG" <<'EOC'
THRESHOLD_BPS=52428800
AUTO_BAN=0
INTERVAL=60
EOC
  chmod 644 "$ABUSE_CFG"

  echo "* * * * * root $ABUSE_SCRIPT >/dev/null 2>&1" > /etc/cron.d/ovpn-abuse
  chmod 644 /etc/cron.d/ovpn-abuse
  touch /var/log/ovpn-abuse.log
}

# ---------- Forensic audit hooks (JSON) ----------
install_audit_hooks(){
  mkdir -p "$AUDIT_DIR"
  touch "$AUDIT_LOG"
  chown nobody:"$GRP" "$AUDIT_LOG" 2>/dev/null || true
  chmod 640 "$AUDIT_LOG"
  chmod 755 "$AUDIT_DIR"

  cat > "$HOOK" <<'EOH'
#!/usr/bin/env bash
# OpenVPN client-connect: ban check + JSON forensics
set -u
BAN_DIR=/etc/openvpn/banned
AUDIT_LOG=/var/log/ovpn/audit.jsonl

CN_RAW="${common_name:-unknown}"
CN_SAFE="${CN_RAW//[^A-Za-z0-9_-]/_}"

jesc() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")

if [[ -f "$BAN_DIR/$CN_SAFE" ]]; then
  logger -t ovpn-hook "Rejected banned client: $CN_RAW (ip=${untrusted_ip:-?})"
  REJECT_JSON="{\"ts\":\"$(jesc "$TS")\",\"event\":\"reject\",\"reason\":\"banned\",\"cn\":\"$(jesc "$CN_RAW")\",\"real_ip\":\"$(jesc "${untrusted_ip:-${trusted_ip:-unknown}}")\"}"
  if ! printf '%s\n' "$REJECT_JSON" >> "$AUDIT_LOG" 2>/dev/null; then
    logger -t ovpn-audit "$REJECT_JSON"
  fi
  exit 1
fi

JSON="{\"ts\":\"$(jesc "$TS")\"\
,\"event\":\"connect\"\
,\"cn\":\"$(jesc "$CN_RAW")\"\
,\"real_ip\":\"$(jesc "${untrusted_ip:-${trusted_ip:-unknown}}")\"\
,\"real_port\":\"$(jesc "${untrusted_port:-${trusted_port:-0}}")\"\
,\"vpn_ip\":\"$(jesc "${ifconfig_pool_remote_ip:-unknown}")\"\
,\"daemon_pid\":\"$(jesc "${daemon_pid:-0}")\"\
,\"device\":\"$(jesc "${dev:-unknown}")\"\
,\"iv_ver\":\"$(jesc "${IV_VER:-}")\"\
,\"iv_plat\":\"$(jesc "${IV_PLAT:-}")\"\
,\"iv_gui_ver\":\"$(jesc "${IV_GUI_VER:-}")\"\
,\"iv_hwaddr\":\"$(jesc "${IV_HWADDR:-}")\"\
,\"iv_ssl\":\"$(jesc "${IV_SSL:-}")\"\
,\"iv_proto\":\"$(jesc "${IV_PROTO:-}")\"\
,\"iv_ciphers\":\"$(jesc "${IV_CIPHERS:-}")\"\
,\"time_ascii\":\"$(jesc "${time_ascii:-}")\"}"

if ! printf '%s\n' "$JSON" >> "$AUDIT_LOG" 2>/dev/null; then
  logger -t ovpn-audit "$JSON"
fi
exit 0
EOH
  chmod 755 "$HOOK"
  chown root:root "$HOOK"

  cat > "$HOOK_DISC" <<'EOH'
#!/usr/bin/env bash
# OpenVPN client-disconnect: JSON forensics
set -u
AUDIT_LOG=/var/log/ovpn/audit.jsonl

jesc() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

TS=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "")

JSON="{\"ts\":\"$(jesc "$TS")\"\
,\"event\":\"disconnect\"\
,\"cn\":\"$(jesc "${common_name:-unknown}")\"\
,\"real_ip\":\"$(jesc "${untrusted_ip:-${trusted_ip:-unknown}}")\"\
,\"vpn_ip\":\"$(jesc "${ifconfig_pool_remote_ip:-unknown}")\"\
,\"bytes_received\":\"$(jesc "${bytes_received:-0}")\"\
,\"bytes_sent\":\"$(jesc "${bytes_sent:-0}")\"\
,\"duration\":\"$(jesc "${time_duration:-0}")\"\
,\"time_ascii\":\"$(jesc "${time_ascii:-}")\"}"

if ! printf '%s\n' "$JSON" >> "$AUDIT_LOG" 2>/dev/null; then
  logger -t ovpn-audit "$JSON"
fi
exit 0
EOH
  chmod 755 "$HOOK_DISC"
  chown root:root "$HOOK_DISC"
}

toggle_autoban(){
  [[ -f $ABUSE_CFG ]] || { msg "Abuse monitor not installed."; return 0; }
  local cur
  cur=$(awk -F= '/^AUTO_BAN=/{print $2}' "$ABUSE_CFG")
  if [[ $cur == "1" ]]; then
    sed -i 's/^AUTO_BAN=.*/AUTO_BAN=0/' "$ABUSE_CFG"
    msg "Auto-ban DISABLED (alerts only)."
  else
    sed -i 's/^AUTO_BAN=.*/AUTO_BAN=1/' "$ABUSE_CFG"
    msg "Auto-ban ENABLED. Clients exceeding thresholds are banned and blocked in the firewall."
  fi
}

view_bans(){
  local body="" f
  shopt -s nullglob
  for f in "$BAN_DIR"/*; do
    body+="$(printf '%-20s ip=%s\n' "$(basename "$f")" "$(cat "$f" 2>/dev/null)")"$'\n'
  done
  [[ -z $body ]] && body="(no banned clients)"
  msg "Banned clients:

$body"
}

remove_ban_rule(){
  local ip=$1
  [[ -z $ip ]] && return 0
  if [[ $ip == *:* ]]; then
    ip6tables -w 5 -D OVPN-BAN -s "$ip" -j DROP 2>/dev/null || true
  else
    iptables  -w 5 -D OVPN-BAN -s "$ip" -j DROP 2>/dev/null || true
  fi
}

unban_client(){
  local files=() f
  shopt -s nullglob
  for f in "$BAN_DIR"/*; do [[ -e $f ]] && files+=("$(basename "$f")" ""); done
  [[ ${#files[@]} -eq 0 ]] && { msg "No banned clients."; return 0; }
  local pick
  pick=$(whiptail --title "$TITLE" --menu "Unban which client?" 20 60 10 \
    "${files[@]}" 3>&1 1>&2 2>&3) || return 0
  local ip
  ip=$(cat "$BAN_DIR/$pick" 2>/dev/null || echo "")
  remove_ban_rule "$ip"
  rm -f "$BAN_DIR/$pick"
  msg "'$pick' unbanned."
}

show_abuse_log(){
