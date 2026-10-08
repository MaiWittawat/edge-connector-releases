#!/bin/sh
# Install, upgrade or remove the CloudCentric edge agent (design doc §9.2):
# fetch the cloudcentric-agent release from the release tree (cc-release),
# verify its sha256 AND its Ed25519 release signature before anything on the
# machine changes, install it under /opt/cloudcentric, enroll the host once,
# and run it as a service — systemd on Linux, launchd on macOS — rolling back
# by itself if a new version does not stay up. The build for this machine's
# OS and CPU (uname) is picked by itself: <version>/<os>_<arch>/manifest.json.
#
#   curl -fsSL https://raw.githubusercontent.com/MaiWittawat/edge-connector-releases/main/install-agent.sh | sudo sh -s -- \
#        --token cce1.host_… --server crm.example.com:443
#
#   sudo sh install-agent.sh --token T --server HOST:PORT [--channel stable | --version V]
#        [--ca-cert-file F] [--tls-server-name N] [--trusted-key id=base64]... [--base-url URL]
#   sudo sh install-agent.sh                      # again = upgrade (same host, same identity)
#   sudo sh install-agent.sh --uninstall [--purge]
#
# The token can also come from the environment (sudo CC_ENROLL_TOKEN=… sh -s -- …);
# it is used once, by `cloudcentric-agent enroll`, and never written to disk.
#
# Layout:
#   /opt/cloudcentric/agent/<version>/bin/cloudcentric-agent   every installed agent version (last 3 kept)
#   /opt/cloudcentric/agent/current -> <version>              what runs (switched atomically)
#   /opt/cloudcentric/bin/cloudcentric-agent -> ../agent/current/bin/cloudcentric-agent
#   /opt/cloudcentric/etc/agent.yaml                          server, trust, releases (0600; never overwritten)
#   /opt/cloudcentric/etc/host.identity.json                  the host's key (0600; kept on upgrade/uninstall)
#   /etc/systemd/system/cloudcentric-agent.service             Linux
#   /Library/LaunchDaemons/com.cloudcentric.agent.plist        macOS (log: /var/log/cloudcentric-agent.log)
#
# Trust chain (what makes a download installable):
#   1. this script — fetched over HTTPS from the release host; the release
#      build bakes the release base URL and the trusted signing keys into it.
#   2. the manifest names the artifact's sha256 and size and carries an Ed25519
#      signature over "cc-artifact:<name>:<version>:<os>:<arch>:<sha256>";
#      the script checks size + sha256 itself, then the signature against a
#      key baked in here or given with --trusted-key:
#        - with OpenSSL >= 3 (independent of anything downloaded), else
#        - with the agent ALREADY installed on this machine (`cloudcentric-agent
#          verify`, which also trusts its compiled-in keys and agent.yaml's) —
#          never with the binary being verified.
#      No way to check the signature = nothing installed (unless
#      --insecure-skip-signature: sha256 only, trust = HTTPS of the base URL).
#   3. the same keys go into agent.yaml (trusted_keys): the agent then checks
#      every plugin it installs the same way.
set -eu
umask 022

BASE_URL="${CC_RELEASE_URL:-https://raw.githubusercontent.com/MaiWittawat/edge-connector-releases/main}"   # the release tree — set by the release build
BAKED_KEYS="release-2026=z+2JAsL/vL5CKT1VlAWn0tpuc6hCWKiMi4C1Wxt9Xdc="                # "key_id=base64 …" — set by the release build
NAME=cloudcentric-agent
ROOT="${CC_ROOT:-/opt/cloudcentric}"
CHANNEL=stable
VERSION=""
TOKEN="${CC_ENROLL_TOKEN:-}"
SERVER=""
CA_FILE=""
TLS_NAME=""
KEYS=""
UNINSTALL=0
PURGE=0
VERIFY_WITH=auto
SKIP_SIG=0
HEALTH_WAIT="${CC_HEALTH_WAIT:-15}"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<EOF
Install, upgrade or remove the CloudCentric edge agent.

  curl -fsSL ${BASE_URL}/install-agent.sh | sudo sh -s -- --token cce1.host_… --server HOST:PORT

options:
  --token T                 host enrollment token (first install only; or CC_ENROLL_TOKEN)
  --server HOST:PORT        the CRM (first install: written to agent.yaml)
  --channel C               release channel to follow (default: stable)
  --version V               install exactly this agent version
  --base-url URL            the release tree (default: ${BASE_URL})
  --ca-cert-file F          a private CA (PEM) for the CRM — copied to <root>/etc/ca.pem
  --tls-server-name N       name to check in the CRM's certificate
  --trusted-key ID=BASE64   another trusted release signing key (repeatable)
  --root DIR                install root (default: /opt/cloudcentric)
  --verify-with W           how to check the signature: auto | openssl | agent (default: auto)
  --insecure-skip-signature sha256 only — trust is then just the HTTPS of the base URL
  --uninstall               stop and remove the agent and its plugins (keeps etc/ and data/)
  --purge                   with --uninstall: delete everything, the host identity too
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--token) TOKEN="$2"; shift 2 ;;
	--server) SERVER="$2"; shift 2 ;;
	--channel) CHANNEL="$2"; shift 2 ;;
	--version) VERSION="$2"; shift 2 ;;
	--base-url) BASE_URL="$2"; shift 2 ;;
	--ca-cert-file) CA_FILE="$2"; shift 2 ;;
	--tls-server-name) TLS_NAME="$2"; shift 2 ;;
	--trusted-key) case "$2" in ?*=?*) ;; *) die "--trusted-key needs ID=BASE64" ;; esac
		KEYS="$KEYS $2"; shift 2 ;;
	--root) ROOT="$2"; shift 2 ;;
	--verify-with) VERIFY_WITH="$2"; shift 2 ;;
	--insecure-skip-signature) SKIP_SIG=1; shift ;;
	--uninstall) UNINSTALL=1; shift ;;
	--purge) PURGE=1; shift ;;
	-h|--help) usage; exit 0 ;;
	*) die "unknown option: $1 (see --help)" ;;
	esac
done
case "$BAKED_KEYS" in __*) BAKED_KEYS="" ;; esac
ALLKEYS="$BAKED_KEYS $KEYS"
case "$VERIFY_WITH" in auto|openssl|agent) ;; *) die "--verify-with: auto | openssl | agent" ;; esac
case "$ROOT" in /?*) ;; *) die "--root must be an absolute path" ;; esac
ROOT=${ROOT%/}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in
x86_64|amd64) ARCH=amd64 ;;
aarch64|arm64) ARCH=arm64 ;;
*) die "unsupported CPU: $(uname -m)" ;;
esac
case "$OS" in
linux) command -v systemctl >/dev/null 2>&1 || die "systemd is required (systemctl not found)" ;;
darwin) command -v launchctl >/dev/null 2>&1 || die "launchctl not found" ;;
*) die "this installer supports Linux (systemd) and macOS (launchd) — this is $OS" ;;
esac
[ "$(id -u)" = 0 ] || die "run as root (sudo)"

BIN="$ROOT/bin/$NAME"
REL="$ROOT/agent"
ETC="$ROOT/etc"
CFG="$ETC/agent.yaml"
UNIT="/etc/systemd/system/$NAME.service"          # linux
LABEL=com.cloudcentric.agent                        # darwin
PLIST="/Library/LaunchDaemons/$LABEL.plist"
MACLOG="/var/log/$NAME.log"
NEWSYSLOG="/etc/newsyslog.d/$NAME.conf"
if [ "$OS" = darwin ]; then LOGHINT="tail -f $MACLOG"; else LOGHINT="journalctl -u $NAME -f"; fi

# launchd: `launchctl print` fails = not loaded; its "state" / "runs" lines otherwise
lc_print() { launchctl print "system/$LABEL" 2>/dev/null; }
lc_field() { lc_print | sed -n "s/^[[:space:]]*$1 = \(.*\)\$/\1/p" | head -n 1; }
lc_stop() { # bootout = SIGTERM, the agent drains its plugins; wait until launchd has let go of it
	lc_print >/dev/null || return 0
	launchctl bootout "system/$LABEL" 2>/dev/null || true
	i=0
	while lc_print >/dev/null && [ $i -lt 200 ]; do sleep 1; i=$((i + 1)); done
}

# ── uninstall ────────────────────────────────────────────────
if [ "$UNINSTALL" = 1 ]; then
	if [ -x "$BIN" ]; then
		if [ "$PURGE" = 1 ]; then "$BIN" uninstall --root "$ROOT" --purge --yes
		else "$BIN" uninstall --root "$ROOT"; fi
	else
		warn "$BIN not found — removing what is left"
	fi
	if [ "$OS" = darwin ]; then
		lc_stop
		rm -f "$PLIST" "$NEWSYSLOG"
	elif [ -f "$UNIT" ]; then
		systemctl disable --now "$NAME" >/dev/null 2>&1 || true
		rm -f "$UNIT"
		systemctl daemon-reload
	fi
	rm -rf "$REL" "$ROOT/bin" "$ROOT/plugins" "$ROOT/run"
	if [ "$PURGE" = 1 ]; then rm -rf "$ROOT"; fi
	say "$NAME removed"
	exit 0
fi

command -v tar >/dev/null || die "tar is required"
if command -v curl >/dev/null 2>&1; then fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then fetch() { wget -q -O "$2" "$1"; }
else die "curl or wget is required"; fi
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$1" | cut -d' ' -f1; }
else sha() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi
case "$BASE_URL" in __*|"") die "no release URL: pass --base-url or set CC_RELEASE_URL" ;; esac
BASE_URL=${BASE_URL%/}

# jget KEY FILE: a string / number field of a JSON file (cc-release writes one
# field per line; compact JSON works too). Only flat, comma-free values.
jget() {
	tr ',{}[]' '\n\n\n\n\n' <"$2" | sed -n "s/^[[:space:]]*\"$1\"[[:space:]]*:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" | head -n 1
}
segment() { case "$1" in ""|.*|*[!A-Za-z0-9._+-]*) return 1 ;; esac; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# ── 1. find the release ──────────────────────────────────────
if [ -z "$VERSION" ]; then
	segment "$CHANNEL" || die "bad channel: $CHANNEL"
	fetch "$BASE_URL/$NAME/channels/$CHANNEL.json" "$TMP/channel.json" || die "cannot read channel $CHANNEL: $BASE_URL/$NAME/channels/$CHANNEL.json"
	VERSION=$(jget version "$TMP/channel.json")
	segment "$VERSION" || die "channel $CHANNEL names no usable version"
	say "channel $CHANNEL → $NAME $VERSION"
fi
segment "$VERSION" || die "bad version: $VERSION"
MURL="$BASE_URL/$NAME/$VERSION/${OS}_${ARCH}/manifest.json"
fetch "$MURL" "$TMP/manifest.json" || die "no $NAME $VERSION for $OS/$ARCH ($MURL)"
M_NAME=$(jget name "$TMP/manifest.json")
M_VERSION=$(jget version "$TMP/manifest.json")
M_OS=$(jget os "$TMP/manifest.json")
M_ARCH=$(jget arch "$TMP/manifest.json")
A_URL=$(jget url "$TMP/manifest.json")
A_SHA=$(jget sha256 "$TMP/manifest.json")
A_SIZE=$(jget size "$TMP/manifest.json")
A_SIG=$(jget signature "$TMP/manifest.json")
A_KID=$(jget keyId "$TMP/manifest.json")
[ "$M_NAME $M_VERSION $M_OS $M_ARCH" = "$NAME $VERSION $OS $ARCH" ] \
	|| die "manifest at $MURL says '$M_NAME $M_VERSION $M_OS/$M_ARCH' — not installing"
case "$A_SHA" in *[!0-9a-f]*|"") die "manifest has no sha256" ;; esac
[ ${#A_SHA} = 64 ] || die "manifest sha256 is not 64 hex characters"
case "$A_URL" in https://*|http://*) ;; *) die "artifact url must be http(s): $A_URL" ;; esac

# ── 2. download + verify (nothing on the system changes before this passes)
say "downloading $NAME $VERSION ($OS/$ARCH)"
fetch "$A_URL" "$TMP/agent.tar.gz" || die "download failed: ${A_URL%%\?*}"
if [ -n "$A_SIZE" ]; then
	GOTSIZE=$(wc -c <"$TMP/agent.tar.gz" | tr -d ' ')
	[ "$GOTSIZE" = "$A_SIZE" ] || die "size mismatch (want $A_SIZE, got $GOTSIZE) — not installing"
fi
GOT=$(sha "$TMP/agent.tar.gz")
[ "$GOT" = "$A_SHA" ] || die "checksum mismatch (want $A_SHA, got $GOT) — not installing"

PUB=""
for kv in $ALLKEYS; do
	if [ -z "$PUB" ] && [ "${kv%%=*}" = "$A_KID" ]; then PUB=${kv#*=}; fi
done

# OpenSSL >= 3: the one on PATH, else Homebrew's (macOS ships LibreSSL, and sudo's PATH has no brew)
OPENSSL=""
for o in openssl /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
	case "$("$o" version 2>/dev/null)" in "OpenSSL "[3-9]*) OPENSSL=$o; break ;; esac
done
openssl3() { [ -n "$OPENSSL" ]; }
if [ "$OS" = darwin ]; then GETSSL="brew install openssl@3"; else GETSSL="apt install openssl"; fi
verify_openssl() {
	[ -n "$A_SIG" ] && [ -n "$A_KID" ] || die "the release is not signed — not installing"
	[ -n "$PUB" ] || die "the release is signed with key '$A_KID', which this installer does not trust (--trusted-key $A_KID=…) — not installing"
	case "$PUB" in
	MCowBQYDK2VwAyEA*) SPKI=$PUB ;;     # already DER SubjectPublicKeyInfo
	*) SPKI="MCowBQYDK2VwAyEA$PUB" ;;  # raw 32 bytes: the 12-byte Ed25519 SPKI header, base64 joins cleanly
	esac
	printf -- '-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n' "$SPKI" >"$TMP/pub.pem"
	printf '%s' "$A_SIG" | "$OPENSSL" base64 -d -A >"$TMP/sig" || die "signature is not base64"
	printf 'cc-artifact:%s:%s:%s:%s:%s' "$NAME" "$VERSION" "$OS" "$ARCH" "$A_SHA" >"$TMP/msg"
	"$OPENSSL" pkeyutl -verify -pubin -inkey "$TMP/pub.pem" -rawin -in "$TMP/msg" -sigfile "$TMP/sig" >/dev/null 2>&1 \
		|| die "BAD SIGNATURE on $NAME $VERSION (key $A_KID) — not installing"
	say "signature ok (key $A_KID, checked with $("$OPENSSL" version | cut -d' ' -f1,2))"
}
verify_agent() { # the agent already installed here — trusted since it was installed
	set --
	for kv in $ALLKEYS; do set -- "$@" --trusted-key "$kv"; done
	"$BIN" verify --root "$ROOT" --manifest "$TMP/manifest.json" --artifact "$TMP/agent.tar.gz" "$@" \
		|| die "the installed agent refused $NAME $VERSION — not installing"
	say "signature ok (key $A_KID, checked by the installed agent $("$BIN" version 2>/dev/null))"
}
if [ "$SKIP_SIG" = 1 ]; then
	warn "--insecure-skip-signature: only the sha256 was checked (trust = HTTPS of $BASE_URL)"
else
	case "$VERIFY_WITH" in
	openssl) openssl3 || die "--verify-with openssl needs OpenSSL 3 or later"; verify_openssl ;;
	agent) [ -x "$BIN" ] || die "--verify-with agent: no agent installed at $BIN"; verify_agent ;;
	auto)
		if openssl3; then verify_openssl
		elif [ -x "$BIN" ] && "$BIN" verify --help >/dev/null 2>&1; then verify_agent
		else die "cannot check the release signature: install OpenSSL 3 ($GETSSL), or pass --insecure-skip-signature"
		fi ;;
	esac
fi

mkdir "$TMP/x"
tar -xzf "$TMP/agent.tar.gz" -C "$TMP/x"
[ -f "$TMP/x/bin/$NAME" ] && [ ! -L "$TMP/x/bin/$NAME" ] || die "archive has no bin/$NAME"
chmod 755 "$TMP/x/bin/$NAME"
NEWVER=$("$TMP/x/bin/$NAME" version 2>/dev/null) || die "the downloaded agent does not run on this machine ($OS/$ARCH)"
[ "$NEWVER" = "$VERSION" ] || warn "the binary says version '$NEWVER', the release says $VERSION"
say "verified $NAME $VERSION"

# ── 3. place the version (old versions untouched) ────────────
mkdir -p "$REL" "$ROOT/bin" "$ETC"
chmod 755 "$ROOT" "$REL" "$ROOT/bin"
chmod 700 "$ETC"
if [ ! -d "$REL/$VERSION" ]; then
	rm -rf "$REL/.$VERSION.tmp"
	cp -R "$TMP/x" "$REL/.$VERSION.tmp"
	chown -R 0:0 "$REL/.$VERSION.tmp"
	mv "$REL/.$VERSION.tmp" "$REL/$VERSION"
fi
PREV=""
if [ -L "$REL/current" ]; then PREV=$(readlink "$REL/current"); fi

# ── 4. agent.yaml (written once; edit it afterwards) ─────────
if [ -f "$CFG" ]; then
	if [ -n "$SERVER$CA_FILE$TLS_NAME$KEYS" ]; then warn "kept the existing $CFG — edit it to change server / ca_cert / trusted_keys"; fi
else
	[ -n "$SERVER" ] || die "--server HOST:PORT is required for the first install"
	CA=""
	if [ -n "$CA_FILE" ]; then
		[ -f "$CA_FILE" ] || die "no such file: $CA_FILE"
		install -m 644 "$CA_FILE" "$ETC/ca.pem"
		CA="$ETC/ca.pem"
	fi
	{
		printf '# %s — written by install-agent.sh; see agent/packaging/agent.yaml for every setting.\n' "$CFG"
		printf 'server: "%s"\n' "$SERVER"
		[ "$ROOT" = /opt/cloudcentric ] || printf 'paths:\n  root: "%s"\n' "$ROOT"
		[ -z "$CA" ] || printf 'ca_cert: "%s"\n' "$CA"
		[ -z "$TLS_NAME" ] || printf 'tls_server_name: "%s"\n' "$TLS_NAME"
		printf 'releases: "%s"\n' "$BASE_URL"
		SEEN=" "
		printf 'trusted_keys:'
		[ -n "$(printf '%s' "$ALLKEYS" | tr -d ' ')" ] || printf ' {}'
		printf '\n'
		for kv in $ALLKEYS; do
			id=${kv%%=*}
			case "$SEEN" in *" $id "*) continue ;; esac
			SEEN="$SEEN$id "
			printf '  %s: "%s"\n' "$id" "${kv#*=}"
		done
	} >"$CFG.tmp"
	chmod 600 "$CFG.tmp"
	mv "$CFG.tmp" "$CFG"
	say "wrote $CFG"
fi

# ── 5. enroll once (the token is never written anywhere) ─────
if [ -f "$ETC/host.identity.json" ]; then
	if [ -n "$TOKEN" ]; then warn "already enrolled ($ETC/host.identity.json) — ignoring the token"; fi
else
	[ -n "$TOKEN" ] || die "not enrolled yet: give --token (or CC_ENROLL_TOKEN)"
	say "enrolling this host"
	CC_ENROLL_TOKEN="$TOKEN" "$REL/$VERSION/bin/$NAME" enroll --root "$ROOT" >/dev/null \
		|| die "enrollment failed — nothing was switched; check the token, --server and the CA"
fi
TOKEN=""

# ── 6. switch + service ──────────────────────────────────────
relink() { # relink TARGET LINK — atomic: a new symlink renamed over the old one (rename(2), never a gap)
	rm -f "$2.new"
	ln -s "$1" "$2.new"
	mv -T "$2.new" "$2" 2>/dev/null || mv -h -f "$2.new" "$2"
	[ "$(readlink "$2")" = "$1" ] || die "could not point $2 at $1"
}

prune() { # keep the newest 3 versions plus the running and the previous one
	ls -1t "$REL" | grep -v '^current$' | tail -n +4 | while read -r v; do
		[ "$v" = "$VERSION" ] || [ "$v" = "$PREV" ] || rm -rf "${REL:?}/$v"
	done
}

if [ "$OS" = linux ]; then
# mirrors agent/packaging/systemd/cloudcentric-agent.service
cat >"$UNIT.tmp" <<EOF
# $NAME — the CloudCentric edge host supervisor. Installed by install-agent.sh.
[Unit]
Description=CloudCentric edge agent
Documentation=https://github.com/MaiWittawat/edge-connector
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
Environment=CC_ROOT=$ROOT
EnvironmentFile=-$ETC/agent.env
ExecStart=$BIN run
Restart=always
RestartSec=5
RestartPreventExitStatus=3
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=180
UMask=0077
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$NAME
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
ReadWritePaths=$ROOT

[Install]
WantedBy=multi-user.target
EOF
mv "$UNIT.tmp" "$UNIT"
systemctl daemon-reload
systemctl enable "$NAME" >/dev/null 2>&1
else
# mirrors agent/packaging/launchd/com.cloudcentric.agent.plist
cat >"$PLIST.tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- $NAME — the CloudCentric edge host supervisor. Installed by install-agent.sh. -->
<plist version="1.0">
<dict>
	<key>Label</key><string>$LABEL</string>
	<key>ProgramArguments</key>
	<array>
		<string>/bin/sh</string>
		<string>-c</string>
		<string>if [ -f '$ETC/agent.env' ]; then set -a; . '$ETC/agent.env'; set +a; fi; exec '$BIN' run</string>
	</array>
	<key>EnvironmentVariables</key>
	<dict><key>CC_ROOT</key><string>$ROOT</string></dict>
	<key>RunAtLoad</key><true/>
	<key>KeepAlive</key><true/>
	<key>ThrottleInterval</key><integer>10</integer>
	<key>ExitTimeOut</key><integer>180</integer>
	<key>Umask</key><integer>63</integer>
	<key>SoftResourceLimits</key>
	<dict><key>NumberOfFiles</key><integer>10240</integer></dict>
	<key>StandardOutPath</key><string>$MACLOG</string>
	<key>StandardErrorPath</key><string>$MACLOG</string>
</dict>
</plist>
EOF
plutil -lint "$PLIST.tmp" >/dev/null || die "the launchd plist does not validate"
chown 0:0 "$PLIST.tmp"
chmod 644 "$PLIST.tmp"
mv "$PLIST.tmp" "$PLIST"
# rotate the log: at 10 MB, 7 kept, bzip2 (N: no signal — launchd reopens it for the next run)
printf '# logfilename [owner:group] mode count size when flags\n%s root:wheel 640 7 10240 * NJ\n' "$MACLOG" >"$NEWSYSLOG"
fi

svc_restart() {
	if [ "$OS" = linux ]; then systemctl restart "$NAME"; return; fi
	lc_stop
	launchctl enable "system/$LABEL" 2>/dev/null || true
	launchctl bootstrap system "$PLIST"
}
svc_runs() { if [ "$OS" = linux ]; then systemctl show -p NRestarts --value "$NAME"; else lc_field runs; fi; }
svc_up() {
	if [ "$OS" = linux ]; then [ "$(systemctl is-active "$NAME")" = active ]
	else [ "$(lc_field state)" = running ]; fi
}
svc_logs() {
	if [ "$OS" = linux ]; then journalctl -u "$NAME" -n 20 --no-pager 2>/dev/null || true
	else tail -n 20 "$MACLOG" 2>/dev/null || true; fi
}
svc_stop() { if [ "$OS" = linux ]; then systemctl stop "$NAME" || true; else lc_stop; fi; }

healthy() { # up, not restarted during the wait, and answering on its control socket
	sleep 1
	r0=$(svc_runs)
	i=0
	while [ $i -lt "$HEALTH_WAIT" ]; do
		svc_up || return 1
		[ "$(svc_runs)" = "$r0" ] || return 1
		sleep 1; i=$((i + 1))
	done
	"$BIN" status --root "$ROOT" --json >"$TMP/status.json" 2>/dev/null || return 1
	! grep -q '"connection": "agent not running"' "$TMP/status.json"
}

relink "$VERSION" "$REL/current"
relink "../agent/current/bin/$NAME" "$BIN"
say "starting $NAME $VERSION"
svc_restart || true
if healthy; then
	prune
	CONN=$(jget connection "$TMP/status.json")
	HOST=$(jget host_id "$TMP/status.json")
	[ "$CONN" = connected ] || warn "the agent runs but is not connected to the CRM yet ($CONN) — see: $NAME doctor"
	say "$NAME $VERSION is running — host ${HOST:-?}, $CONN ($LOGHINT · $NAME status)"
	exit 0
fi

svc_logs
if [ -n "$PREV" ] && [ "$PREV" != "$VERSION" ] && [ -d "$REL/$PREV" ]; then
	warn "$NAME $VERSION did not stay up — rolling back to $PREV"
	relink "$PREV" "$REL/current"
	svc_restart || true
	if healthy; then die "upgrade to $VERSION failed; $PREV is running again"; fi
	die "upgrade to $VERSION failed and $PREV does not stay up either — see: $LOGHINT"
fi
svc_stop
die "$NAME $VERSION does not stay up — see: $LOGHINT and: $BIN doctor"
