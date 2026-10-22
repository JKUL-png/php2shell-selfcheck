#!/usr/bin/env bash
# Tests for php2shell-selfcheck.sh using fake PHP binaries. No network, no root needed.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../php2shell-selfcheck.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

fake_php() { # fake_php NAME VERSION [SAPI]
  local f="$TMP/bin/$1"
  mkdir -p "$TMP/bin"
  printf '#!/bin/sh\necho "PHP %s (%s) (built: Oct 21 2026 10:00:00) (NTS)"\n' "$2" "${3:-cli}" > "$f"
  chmod +x "$f"
  printf '%s\n' "$f"
}

expect() { # expect "description" expected_exit expected_text -- command...
  local desc="$1" want="$2" text="$3"; shift 4
  local out code
  out="$("$@" 2>&1)"; code=$?
  if [ "$code" -eq "$want" ] && printf '%s' "$out" | grep -qF -- "$text"; then
    PASS=$((PASS + 1)); printf 'ok   %s\n' "$desc"
  else
    FAIL=$((FAIL + 1)); printf 'FAIL %s (exit %s, wanted %s; text "%s")\n%s\n' "$desc" "$code" "$want" "$text" "$out"
  fi
}

run() { NO_COLOR=1 PHP2SHELL_SKIP_PROC=1 PHP2SHELL_SEARCH_PATHS="$TMP/none*" bash "$SCRIPT" --no-color --only "$@"; }

for v in 8.5.12 8.4.27 8.3.36 8.2.35 8.4.30; do
  b="$(fake_php "php-ok-$v" "$v")"
  expect "fixed version $v is patched" 0 "[PATCHED]" -- run --php "$b"
done

for v in 8.5.11 8.4.26 8.3.35 8.2.34 8.3.6; do
  b="$(fake_php "php-bad-$v" "$v")"
  expect "old version $v is vulnerable" 1 "[VULNERABLE]" -- run --php "$b"
done

for v in 8.1.31 8.0.30 7.4.33 5.6.40; do
  b="$(fake_php "php-eol-$v" "$v")"
  expect "end-of-life $v flagged" 1 "no official fix" -- run --php "$b"
done

b="$(fake_php "php-fpm8.4" "8.4.27" "fpm-fcgi")"
expect "fpm binary is read and patched" 0 "(fpm-fcgi)" -- run --php "$b"

mkdir -p "$TMP/bin"; printf '#!/bin/sh\necho garbage\n' > "$TMP/bin/php-weird"; chmod +x "$TMP/bin/php-weird"
expect "unreadable version is unknown" 2 "could not read the version" -- run --php "$TMP/bin/php-weird"

expect "nothing found is unknown" 2 "No PHP binary found" -- run

ok_bin="$(fake_php "php-mix-ok" "8.4.27")"; bad_bin="$(fake_php "php-mix-bad" "8.2.20")"
expect "one bad among good fails" 1 "1 PHP installation(s) not patched" -- run --php "$ok_bin" --php "$bad_bin"

# Discovery through search paths
mkdir -p "$TMP/disc"; fake_php "x" "8.3.36" >/dev/null; cp "$TMP/bin/x" "$TMP/disc/php8.3"; cp "$TMP/bin/x" "$TMP/disc/php-config"
expect "discovery finds php8.3 and ignores php-config" 0 "disc/php8.3" -- env NO_COLOR=1 PHP2SHELL_SKIP_PROC=1 PHP2SHELL_SEARCH_PATHS="$TMP/disc/php*" bash "$SCRIPT" --no-color
out="$(NO_COLOR=1 PHP2SHELL_SKIP_PROC=1 PHP2SHELL_SEARCH_PATHS="$TMP/disc/php*" bash "$SCRIPT" --no-color 2>&1)"
if printf '%s' "$out" | grep -q 'php-config'; then FAIL=$((FAIL + 1)); echo "FAIL php-config should be ignored"; else PASS=$((PASS + 1)); echo "ok   php-config ignored"; fi

# Indicators in a web root
W="$TMP/www"; mkdir -p "$W/wp-content/uploads/2026/10"
echo '<?php' > "$W/index.php"; touch -d '2026-09-01' "$W/index.php"
echo '<?php' > "$W/wp-content/uploads/2026/10/x.php"
expect "uploads php file is flagged" 0 "uploads' folder" -- run --php "$(fake_php p "8.4.27")" --webroot "$W"
expect "recent and back-dated php files are counted" 0 "2 PHP file(s) modified or with metadata changed" -- run --php "$(fake_php p2 "8.4.27")" --webroot "$W"

L="$TMP/error.log"; printf 'PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted\nother\nPHP Fatal error:  Allowed memory size of 1 bytes exhausted\n' > "$L"
expect "memory errors are counted" 0 "2 'Allowed memory size' error(s)" -- run --php "$(fake_php p3 "8.4.27")" --log "$L"

# Ubuntu backport detection with a fake dpkg (version number stays 8.3.6, package is patched).
FD="$TMP/fakedpkg"; mkdir -p "$FD"
REAL_DPKG="$(command -v dpkg || true)"
cat > "$FD/dpkg" <<EOF
#!/bin/sh
if [ "\$1" = "-S" ]; then echo "php8.3-cli: \$2"; exit 0; fi
if [ "\$1" = "--compare-versions" ] && [ -n "$REAL_DPKG" ]; then exec "$REAL_DPKG" "\$@"; fi
exit 1
EOF
cat > "$FD/dpkg-query" <<'EOF'
#!/bin/sh
case "$*" in
  *source:Package*) echo "php8.3" ;;
  *) echo "${FAKE_DEB_VERSION}" ;;
esac
EOF
chmod +x "$FD/dpkg" "$FD/dpkg-query"
ub="$(fake_php "php8.3-ubuntu" "8.3.6")"
if [ -n "$REAL_DPKG" ]; then
  expect "Ubuntu 24.04 patched package is recognized" 0 "fixed by your distribution" -- env PATH="$FD:$PATH" FAKE_DEB_VERSION="8.3.6-0ubuntu0.24.04.13" NO_COLOR=1 PHP2SHELL_SKIP_PROC=1 PHP2SHELL_SEARCH_PATHS=/none bash "$SCRIPT" --no-color --only --php "$ub"
  expect "Ubuntu 24.04 older package is vulnerable" 1 "Ubuntu 24.04 fix is" -- env PATH="$FD:$PATH" FAKE_DEB_VERSION="8.3.6-0ubuntu0.24.04.12" NO_COLOR=1 PHP2SHELL_SKIP_PROC=1 PHP2SHELL_SEARCH_PATHS=/none bash "$SCRIPT" --no-color --only --php "$ub"
else
  echo "skip Ubuntu backport tests (dpkg not installed)"
fi

# Review fixes
b="$(fake_php "php-rc" "8.5.12RC1")"
expect "release candidate is not trusted" 2 "pre-release build" -- run --php "$b"
b="$(fake_php "php-devb" "8.4.27-dev")"
expect "dev build is not trusted" 2 "pre-release build" -- run --php "$b"
b="$(fake_php "php-next" "8.6.0")"
expect "newer branch 8.6 is not called end of life" 0 "newer branch" -- run --php "$b"
b="$(fake_php "php-ubu22" "8.1.2-1ubuntu2.28")"
expect "Ubuntu-style suffix is not a pre-release" 1 "[VULNERABLE]" -- run --php "$b"
b="$(fake_php "php-ok-nonroot" "8.4.27")"
expect "without root the result is incomplete, not patched" 2 "running processes not checked" -- env PHP2SHELL_TEST_NONROOT=1 NO_COLOR=1 PHP2SHELL_SEARCH_PATHS="$TMP/none*" bash "$SCRIPT" --no-color --only --php "$b"
if [ "$(id -u)" -eq 0 ]; then
  b="$(fake_php "php-gw" "8.4.27")"; chmod 775 "$b"
  expect "group-writable binary is not executed" 2 "not executed for safety" -- run --php "$b"
fi
mkdir -p "$TMP/bin"; printf '#!/bin/sh\nread x\necho "PHP 8.4.27 (cli)"\n' > "$TMP/bin/php-stdin"; chmod +x "$TMP/bin/php-stdin"
expect "binary waiting on stdin does not hang" 0 "[PATCHED]" -- run --php "$TMP/bin/php-stdin"

expect "help works" 0 "Exit codes" -- bash "$SCRIPT" --help
expect "unknown option fails" 2 "Unknown option" -- bash "$SCRIPT" --bogus

# Safety: the script must not contain network tools.
if grep -vE '^[[:space:]]*#' "$SCRIPT" | grep -qE '\b(curl|wget|nc|ncat|telnet|ssh|scp)\b'; then
  FAIL=$((FAIL + 1)); echo "FAIL script references a network tool"; grep -nE '\b(curl|wget|nc|ncat|telnet|ssh|scp)\b' "$SCRIPT"
else
  PASS=$((PASS + 1)); echo "ok   no network tools in the script"
fi

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
