#!/usr/bin/env bash
# php2shell-selfcheck — check YOUR OWN server for PHP2Shell
# (CVE-2026-109618 / CVE-2026-109619).
#
# What this script does:
#   - Finds PHP installations on this machine and reads their version (-v).
#   - Compares them with the fixed versions published by PHP on 2026-10-21.
#   - Looks for distro backports (known Ubuntu package versions, Debian/RPM changelogs).
#   - Flags Apache mod_php, processes still running an old (deleted) PHP,
#     and running PHP processes it couldn't check.
#   - Optionally lists simple indicators of compromise in a web root you own.
#
# What it never does:
#   - It makes NO network requests.
#   - It changes NOTHING on your system (read-only).
#   - It does not test for, trigger or exploit the vulnerability.
#
# Requirements: bash 4+, GNU coreutils/findutils (standard on Debian, Ubuntu, RHEL and clones).
# License: MIT. Use only on systems you own or are authorized to administer.

set -u

SCRIPT_VERSION="1.1.0"
CVES="CVE-2026-109618 / CVE-2026-109619"
CVE_REGEX='CVE-2026-10961[89]'
IOC_SINCE="2026-10-17"   # earliest exploitation attempt reported (Amazon MadPot)
NEWEST_KNOWN_BRANCH="8.5"

# Fixed upstream versions per supported branch (PHP release of 2026-10-21).
fixed_for_branch() {
  case "$1" in
    8.5) echo "8.5.12" ;;
    8.4) echo "8.4.27" ;;
    8.3) echo "8.3.36" ;;
    8.2) echo "8.2.35" ;;
    *)   echo "" ;;
  esac
}

# Known patched distro packages that keep an older upstream number.
# Format: <version prefix identifying the distro line>|<first fixed package version>|<label>
DISTRO_FIXES=(
  "8.1.2-1ubuntu|8.1.2-1ubuntu2.28|Ubuntu 22.04"
  "8.3.6-0ubuntu0.24.04|8.3.6-0ubuntu0.24.04.13|Ubuntu 24.04"
  "8.5.4-0ubuntu|8.5.4-0ubuntu1.5|Ubuntu 26.04"
)

# ---------- output helpers ----------
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_RST=""
fi
disable_color() { C_RED=""; C_GRN=""; C_YEL=""; C_BLD=""; C_RST=""; }

say()  { printf '%s\n' "$*"; }
head1() { printf '\n%s%s%s\n' "$C_BLD" "$*" "$C_RST"; }
ok()   { printf '  %s[PATCHED]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
bad()  { printf '  %s[VULNERABLE]%s %s\n' "$C_RED" "$C_RST" "$*"; }
warn() { printf '  %s[WARNING]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
unk()  { printf '  %s[UNKNOWN]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
info() { printf '  - %s\n' "$*"; }

usage() {
  cat <<EOF
php2shell-selfcheck $SCRIPT_VERSION — read-only check for $CVES on your own server.

Usage: sudo bash php2shell-selfcheck.sh [options]

Options:
  --php PATH        Also check this PHP binary (repeatable).
  --only            Check only the binaries given with --php (skip auto-discovery).
  --webroot DIR     List PHP files modified since $IOC_SINCE in DIR (repeatable).
  --log FILE        Count out-of-memory errors in this log file (repeatable).
  --no-color        Disable colors.
  -h, --help        Show this help.
  --version         Show version.

Exit codes:
  0  every PHP found is patched and no old PHP is still running
  1  at least one PHP is vulnerable, or on an unsupported branch with no fix found
  2  something could not be checked (no PHP found, unreadable version,
     running PHP outside the checked paths, or not run with sudo)
  3  patched on disk, but some processes still run the old PHP (restart needed)

Run it with sudo: without it, running processes can't be checked and the result is at best 2.
It makes no network requests and changes nothing.
EOF
}

# ---------- argument parsing ----------
EXTRA_BINS=(); WEBROOTS=(); LOGS=(); ONLY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --php) [ $# -ge 2 ] || { say "--php needs a path"; exit 2; }; EXTRA_BINS+=("$2"); shift 2 ;;
    --only) ONLY=1; shift ;;
    --webroot) [ $# -ge 2 ] || { say "--webroot needs a directory"; exit 2; }; WEBROOTS+=("$2"); shift 2 ;;
    --log) [ $# -ge 2 ] || { say "--log needs a file"; exit 2; }; LOGS+=("$2"); shift 2 ;;
    --no-color) disable_color; shift ;;
    -h|--help) usage; exit 0 ;;
    --version) say "$SCRIPT_VERSION"; exit 0 ;;
    *) say "Unknown option: $1 (use --help)"; exit 2 ;;
  esac
done

IS_ROOT=0
[ "$(id -u)" -eq 0 ] && IS_ROOT=1
[ "${PHP2SHELL_TEST_NONROOT:-}" = "1" ] && IS_ROOT=0   # used by the test suite

# ---------- helpers ----------
# ver_ge A B -> true if upstream version A >= B (e.g. 8.3.36)
ver_ge() {
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# deb_ge A B -> true if Debian package version A >= B
deb_ge() {
  command -v dpkg >/dev/null 2>&1 && dpkg --compare-versions "$1" ge "$2"
}

# run_quiet CMD... -> run with a 5s timeout and no stdin (if `timeout` exists)
run_quiet() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 5 "$@" </dev/null 2>/dev/null
  else
    "$@" </dev/null 2>/dev/null
  fi
}

# Only execute binaries owned by root and not writable by group/others (when running as root).
safe_to_run() {
  local bin="$1" owner mode
  [ "$IS_ROOT" -eq 1 ] || return 0
  owner="$(stat -c '%u' "$bin" 2>/dev/null)"; mode="$(stat -c '%a' "$bin" 2>/dev/null)"
  [ "$owner" = "0" ] || return 1
  case "$mode" in
    *[2367][0-7]|*[2367]) return 1 ;;   # group- or other-writable
  esac
  return 0
}

# version_line BIN -> first line of "BIN -n -v" (falls back to "-v"); runs at most twice
version_line() {
  local bin="$1" line
  line="$(run_quiet "$bin" -n -v | head -n1)"
  [ -n "$line" ] || line="$(run_quiet "$bin" -v | head -n1)"
  printf '%s\n' "$line"
}

# parse_version LINE -> "x.y.z suffix" ("PHP 8.3.6 (cli)", "PHP 8.5.12RC1 (cli)", "FrankenPHP ... PHP 8.4.27 ...")
parse_version() {
  printf '%s\n' "$1" | sed -n 's/^.*PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\)\([A-Za-z0-9.~+-]*\).*$/\1 \2/p' | head -n1
}

parse_sapi() {
  printf '%s\n' "$1" | sed -n 's/^PHP [^ ]* (\([^)]*\)).*/\1/p'
}

is_php_name() {
  case "$(basename "$1")" in
    php|php[0-9]*|php-fpm|php-fpm[0-9]*|php[0-9]*-fpm|lsphp|lsphp[0-9]*|php-cgi|php-cgi[0-9]*|php[0-9]*-cgi|frankenphp) return 0 ;;
    *) return 1 ;;
  esac
}

# dpkg package owning a file (handles diversions and "pkg1, pkg2: path")
deb_pkg_of() {
  command -v dpkg >/dev/null 2>&1 || return 1
  local pkg
  pkg="$(dpkg -S "$1" 2>/dev/null | grep -v '^diversion' | head -n1 | sed 's/: [^:]*$//; s/,.*//; s/:.*$//')"
  [ -n "$pkg" ] || return 1
  printf '%s\n' "$pkg"
}

deb_version_of() { dpkg-query -W -f='${Version}' "$1" 2>/dev/null; }

# backport_evidence PATH -> returns 0 if a distro fix is evident; prints an explanation.
# Lines starting with NOFIX/INFO are explanations for the not-fixed case.
backport_evidence() {
  local bin="$1" pkg ver ver_noepoch entry prefix rest fixed label cl top
  pkg="$(deb_pkg_of "$bin")" || pkg=""
  if [ -n "$pkg" ]; then
    ver="$(deb_version_of "$pkg")"
    ver_noepoch="${ver#*:}"
    for entry in "${DISTRO_FIXES[@]}"; do
      prefix="${entry%%|*}"; rest="${entry#*|}"; fixed="${rest%%|*}"; label="${rest#*|}"
      case "$ver_noepoch" in
        "$prefix"*)
          if deb_ge "$ver_noepoch" "$fixed"; then
            printf 'package %s %s (%s fix is %s or later)\n' "$pkg" "$ver" "$label" "$fixed"; return 0
          fi
          printf 'NOFIX package %s %s; the %s fix is %s or later\n' "$pkg" "$ver" "$label" "$fixed"; return 1 ;;
      esac
    done
    # Debian-style changelog of the owning package. Only trusted if its newest entry
    # is the installed version (so every entry describes this build or older).
    cl="/usr/share/doc/$pkg/changelog.Debian.gz"
    if [ -f "$cl" ] && command -v zcat >/dev/null 2>&1; then
      top="$(zcat "$cl" 2>/dev/null | head -n1 | sed -n 's/^[^ ]* (\([^)]*\)).*/\1/p')"
      if [ -n "$top" ] && { [ "$top" = "$ver" ] || [ "$top" = "$ver_noepoch" ]; }; then
        if zcat "$cl" 2>/dev/null | grep -qE "$CVE_REGEX"; then
          printf 'changelog of %s %s mentions the CVEs\n' "$pkg" "$ver"; return 0
        fi
      fi
    fi
    printf 'INFO package %s %s; no fix evidence found in its version or changelog\n' "$pkg" "$ver"
    return 1
  fi
  if command -v rpm >/dev/null 2>&1; then
    pkg="$(rpm -qf "$bin" 2>/dev/null | head -n1)"
    if [ -n "$pkg" ] && ! printf '%s' "$pkg" | grep -q 'not owned'; then
      if rpm -q --changelog "$pkg" 2>/dev/null | grep -qE "$CVE_REGEX"; then
        printf 'changelog of %s mentions the CVEs\n' "$pkg"; return 0
      fi
      printf 'INFO package %s; no CVE in its changelog yet. Some streams only say "rebase": compare with the fixed versions, or check "dnf updateinfo list --security"\n' "$pkg"
      return 1
    fi
  fi
  return 1
}

# ---------- discovery ----------
SEARCH_PATHS_DEFAULT="/usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /usr/local/sbin/php* /usr/local/bin/frankenphp \
/usr/lib/cgi-bin/php* \
/opt/remi/php*/root/usr/bin/php /opt/remi/php*/root/usr/sbin/php-fpm \
/opt/rh/rh-php*/root/usr/bin/php /opt/rh/rh-php*/root/usr/sbin/php-fpm \
/opt/cpanel/ea-php*/root/usr/bin/php /opt/cpanel/ea-php*/root/usr/sbin/php-fpm \
/opt/alt/php*/usr/bin/php /opt/alt/php*/usr/sbin/php-fpm \
/opt/bitnami/php/bin/php /opt/bitnami/php/sbin/php-fpm \
/usr/local/lsws/lsphp*/bin/php /usr/local/lsws/lsphp*/bin/lsphp \
/opt/plesk/php/*/bin/php /opt/plesk/php/*/sbin/php-fpm /usr/local/php*/bin/php /usr/local/php*/sbin/php-fpm"
SEARCH_PATHS="${PHP2SHELL_SEARCH_PATHS:-$SEARCH_PATHS_DEFAULT}"

declare -A SEEN=()
BINS=()
add_bin() {
  local b="$1" real
  [ -x "$b" ] && [ -f "$b" ] || return
  real="$(readlink -f "$b" 2>/dev/null || printf '%s' "$b")"
  [ -n "${SEEN[$real]+x}" ] && return
  SEEN[$real]=1
  BINS+=("$real")
}

if [ "$ONLY" -eq 0 ]; then
  if command -v php >/dev/null 2>&1 && [ -z "${PHP2SHELL_SEARCH_PATHS:-}" ]; then
    add_bin "$(command -v php)"
  fi
  for pattern in $SEARCH_PATHS; do
    for f in $pattern; do
      [ -e "$f" ] || continue
      is_php_name "$f" || continue
      add_bin "$f"
    done
  done
fi
for b in "${EXTRA_BINS[@]+"${EXTRA_BINS[@]}"}"; do add_bin "$b"; done

# ---------- report ----------
say "${C_BLD}php2shell-selfcheck $SCRIPT_VERSION${C_RST} — $CVES"
say "Read-only. No network requests. Only use on systems you own or administer."
[ "$IS_ROOT" -eq 1 ] || say "${C_YEL}Not running as root:${C_RST} running processes won't be checked. Use sudo for a complete result."

N_VULN=0; N_OK=0; N_UNKNOWN=0; N_RESTART=0; NOTES=()

head1 "1. PHP installations"
if [ "${#BINS[@]}" -eq 0 ]; then
  info "No PHP binary found in the usual places."
  info "Docker: run this script inside the container (see README), or check your image tag."
  info "Shared hosting: use php2shell-check.php instead (see README)."
  N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("no PHP binary found")
fi

for bin in "${BINS[@]+"${BINS[@]}"}"; do
  if ! safe_to_run "$bin"; then
    unk "$bin — not owned by root or writable by other users; not executed for safety. Check it manually."
    N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("$bin not executed"); continue
  fi
  line="$(version_line "$bin")"
  parsed="$(parse_version "$line")"
  v="${parsed%% *}"; suffix="${parsed#* }"; [ "$suffix" = "$parsed" ] && suffix=""
  sapi="$(parse_sapi "$line")"
  if [ -z "$v" ]; then
    unk "$bin — could not read the version"
    N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("unreadable version: $bin"); continue
  fi
  label="$bin — PHP $v$suffix${sapi:+ ($sapi)}"
  branch="${v%.*}"; major="${branch%%.*}"; minor="${branch#*.}"
  fixed="$(fixed_for_branch "$branch")"

  case "$suffix" in
    *[Rr][Cc]*|*alpha*|*beta*|*dev*)
      unk "$label — pre-release build. Use a final release (8.5.12, 8.4.27, 8.3.36, 8.2.35 or newer)."
      N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("pre-release PHP: $bin"); continue ;;
  esac

  if [ -n "$fixed" ] && ver_ge "$v" "$fixed"; then
    ok "$label (fixed in $fixed)"; N_OK=$((N_OK + 1)); continue
  fi

  if [ -z "$fixed" ] && ver_ge "$branch" "$NEWEST_KNOWN_BRANCH" && [ "$branch" != "$NEWEST_KNOWN_BRANCH" ]; then
    ok "$label — newer branch than $NEWEST_KNOWN_BRANCH, released after the fix. Confirm in its release notes."
    N_OK=$((N_OK + 1)); continue
  fi

  evidence="$(backport_evidence "$bin")"; has_fix=$?
  if [ "$has_fix" -eq 0 ]; then
    ok "$label — fixed by your distribution: $evidence"; N_OK=$((N_OK + 1)); continue
  fi

  if [ -n "$fixed" ]; then
    bad "$label — needs $fixed or later (or a patched distro package)"
  else
    bad "$label — PHP $major.$minor gets no official fix (end of life), and no distro fix was found"
  fi
  case "$evidence" in
    NOFIX*) info "${evidence#NOFIX }" ;;
    INFO*)  info "${evidence#INFO }" ;;
  esac
  N_VULN=$((N_VULN + 1))
done

head1 "2. Apache mod_php (most exposed setup)"
MODPHP=""
if [ "$IS_ROOT" -eq 1 ]; then
  for ctl in apache2ctl apachectl httpd; do
    command -v "$ctl" >/dev/null 2>&1 || continue
    mods="$(run_quiet "$ctl" -M)"
    if [ -n "$mods" ]; then
      if printf '%s\n' "$mods" | grep -qi 'php'; then
        MODPHP="loaded (reported by $ctl -M)"
      else
        MODPHP="none"
      fi
      break
    fi
  done
fi
if [ -z "$MODPHP" ]; then
  for f in /etc/apache2/mods-enabled/php*.load /etc/httpd/conf.modules.d/*php*.conf /etc/apache2/conf.modules.d/*php*.conf; do
    [ -e "$f" ] || continue
    if grep -qiE '^[[:space:]]*LoadModule[[:space:]]+php' "$f" 2>/dev/null; then
      if grep -qi 'IfModule.*prefork' "$f" 2>/dev/null; then
        MODPHP="configured in $f, but only with the prefork MPM (run with sudo to confirm)"
      else
        MODPHP="enabled in $f"
      fi
      break
    fi
  done
fi
case "$MODPHP" in
  ""|none) info "mod_php not detected." ;;
  *)
    warn "mod_php $MODPHP"
    info "PHP says mod_php is the configuration most exposed to this bug."
    info "After updating, fully stop and start Apache; 'reload' or 'graceful' keeps the old PHP loaded." ;;
esac

head1 "3. Running PHP processes"
if [ "$IS_ROOT" -ne 1 ] || [ "${PHP2SHELL_SKIP_PROC:-}" = "1" ]; then
  if [ "$IS_ROOT" -ne 1 ]; then
    info "Skipped: needs sudo."
    N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("running processes not checked (run with sudo)")
  else
    info "Skipped."
  fi
else
  stale=""; unchecked=""
  declare -A REPORTED=()
  for d in /proc/[0-9]*; do
    pid="${d#/proc/}"
    maps="$d/maps"; [ -r "$maps" ] || continue
    if grep -qE '/[^ ]*php[^ ]* \(deleted\)$' "$maps" 2>/dev/null; then
      stale="$stale $pid($(cat "$d/comm" 2>/dev/null))"
    fi
    exe="$(readlink "$d/exe" 2>/dev/null)"; exe="${exe% (deleted)}"
    [ -n "$exe" ] || continue
    if is_php_name "$exe" || grep -q 'libphp' "$maps" 2>/dev/null; then
      real="$(readlink -f "/proc/$pid/root$exe" 2>/dev/null || printf '%s' "$exe")"
      key="$exe"
      if is_php_name "$exe" && [ -z "${SEEN[$exe]+x}" ] && [ -z "${SEEN[$real]+x}" ] && [ -z "${REPORTED[$key]+x}" ]; then
        REPORTED[$key]=1
        unchecked="$unchecked\n      $exe (pid $pid$( [ "$(readlink "/proc/$pid/ns/mnt" 2>/dev/null)" != "$(readlink /proc/self/ns/mnt 2>/dev/null)" ] && printf ', inside a container'))"
      fi
      lib="$(grep -oE '/[^ ]*libphp[^ ]*\.so' "$maps" 2>/dev/null | head -n1)"
      if [ -n "$lib" ] && [ -z "${REPORTED[$lib]+x}" ]; then
        REPORTED[$lib]=1
        if ev="$(backport_evidence "$lib")"; then
          ok "Apache PHP module $lib — $ev"
        else
          lpkg="$(deb_pkg_of "$lib")" || lpkg=""
          lver=""; [ -n "$lpkg" ] && lver="$(deb_version_of "$lpkg")"
          lup="${lver#*:}"; lup="${lup%%-*}"; lbr="${lup%.*}"; lfix="$(fixed_for_branch "$lbr")"
          if [ -n "$lfix" ] && ver_ge "$lup" "$lfix"; then
            ok "Apache PHP module $lib — package $lpkg $lver"
          elif [ -n "$lup" ]; then
            bad "Apache PHP module $lib — package $lpkg $lver is not a fixed version"
            N_VULN=$((N_VULN + 1))
          else
            unk "Apache PHP module $lib is loaded but its version couldn't be determined. Check it manually."
            N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("unchecked Apache module $lib")
          fi
        fi
      fi
    fi
  done
  if [ -n "$stale" ]; then
    warn "These processes still use a PHP file that was replaced on disk:$stale"
    info "Restart PHP-FPM, Apache (full stop/start), LiteSpeed lsphp (pkill lsphp) and queue workers."
    N_RESTART=1
  fi
  if [ -n "$unchecked" ]; then
    unk "Running PHP not covered by section 1:$(printf '%b' "$unchecked")"
    info "Check these with --php PATH, or run this script inside the container."
    N_UNKNOWN=$((N_UNKNOWN + 1)); NOTES+=("running PHP outside the checked paths")
  fi
  [ -z "$stale" ] && [ -z "$unchecked" ] && info "No problems found in running processes."
fi

if [ "${#WEBROOTS[@]}" -gt 0 ] || [ "${#LOGS[@]}" -gt 0 ]; then
  head1 "4. Simple signs worth a look (hints, not proof)"
  for dir in "${WEBROOTS[@]+"${WEBROOTS[@]}"}"; do
    if [ ! -d "$dir" ]; then warn "$dir is not a directory"; continue; fi
    # -newerct also catches files whose modification time was faked (inode change time).
    count="$(find "$dir" -type f -name '*.php' \( -newermt "$IOC_SINCE" -o -newerct "$IOC_SINCE" \) 2>/dev/null | wc -l | tr -d ' ')"
    info "$dir: $count PHP file(s) modified or with metadata changed since $IOC_SINCE"
    if [ "$count" -gt 0 ]; then
      find "$dir" -type f -name '*.php' \( -newermt "$IOC_SINCE" -o -newerct "$IOC_SINCE" \) 2>/dev/null | head -n 20 | sed 's/^/      /'
      [ "$count" -gt 20 ] && info "(showing the first 20)"
      info "Updates, restores and copies also show up here. Look for files you don't recognize."
    fi
    up="$(find "$dir" -type f -name '*.php' -path '*uploads*' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$up" -gt 0 ]; then
      warn "$up PHP file(s) inside an 'uploads' folder in $dir. Uploads folders normally contain no PHP."
      find "$dir" -type f -name '*.php' -path '*uploads*' 2>/dev/null | head -n 10 | sed 's/^/      /'
    fi
  done
  for lf in "${LOGS[@]+"${LOGS[@]}"}"; do
    if [ ! -r "$lf" ]; then warn "Cannot read $lf"; continue; fi
    if ! command -v zgrep >/dev/null 2>&1; then warn "zgrep not installed; $lf not checked"; continue; fi
    n="$(zgrep -c 'Allowed memory size' "$lf" 2>/dev/null | awk -F: '{s+=$NF} END {print s+0}')"
    info "$lf: $n 'Allowed memory size' error(s)"
    [ "$n" -gt 0 ] && info "Bursts of these errors next to HTTP 500s are one of the signs researchers describe."
  done
fi

head1 "Summary"
if [ "$N_VULN" -gt 0 ]; then
  say "${C_RED}${C_BLD}Action needed:${C_RST} $N_VULN PHP installation(s) not patched."
  say "  1. Update PHP to 8.5.12, 8.4.27, 8.3.36 or 8.2.35 (or your distro's patched package)."
  say "  2. Restart every PHP process (PHP-FPM, full Apache stop/start, lsphp, queue workers)."
  say "  3. Run this script again."
  say "  4. On 8.1 or older: upgrade to 8.4/8.5, or use a vendor that backported the fix."
  say "  5. If you can't patch now, consider taking the site offline (CISA guidance)."
  say "  6. Check for signs of compromise since $IOC_SINCE (use --webroot and --log)."
  exit 1
elif [ "$N_RESTART" -eq 1 ]; then
  say "${C_YEL}${C_BLD}Almost done:${C_RST} patched on disk, but some processes still run the old PHP. Restart them and run this again."
  exit 3
elif [ "$N_UNKNOWN" -gt 0 ]; then
  say "${C_YEL}${C_BLD}Incomplete:${C_RST} nothing vulnerable was found, but some things could not be checked:"
  for n in "${NOTES[@]}"; do say "  - $n"; done
  exit 2
elif [ "$N_OK" -gt 0 ]; then
  say "${C_GRN}${C_BLD}All PHP installations found are patched.${C_RST}"
  say "This means the versions are fixed, not that the server was never compromised."
  say "Also check other servers and your hosting panel if PHP runs elsewhere."
  exit 0
else
  say "${C_YEL}${C_BLD}Could not determine the status.${C_RST}"
  exit 2
fi
