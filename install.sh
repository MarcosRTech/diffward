#!/bin/sh
# diffward installer for macOS and Linux.
#
#   curl -fsSL https://github.com/MarcosRTech/diffward/releases/latest/download/install.sh | sh
#
# Environment:
#   DIFFWARD_VERSION      tag to install, e.g. v0.2.0 (default: latest release)
#   DIFFWARD_INSTALL_DIR  where to put the binary (default: ~/.local/bin)
#   DIFFWARD_FORCE=1      reinstall even if that version is already installed
#   NO_COLOR=1            plain output
set -eu

REPO="MarcosRTech/diffward"
INSTALL_DIR="${DIFFWARD_INSTALL_DIR:-$HOME/.local/bin}"
STEPS=4

# ------------------------------------------------------------------ output

if [ -t 1 ]; then INTERACTIVE=1; else INTERACTIVE=0; fi
if [ "$INTERACTIVE" = 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RED=$(printf '\033[31m')
  GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); CYAN=$(printf '\033[36m'); RESET=$(printf '\033[0m')
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; CYAN=""; RESET=""
fi
case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
  *UTF-8* | *utf8* | *UTF8* | *utf-8*) FULL="█"; EMPTY="░"; OK="✔"; ERR="✖"; WARN="!"; DOT="·" ;;
  *) FULL="#"; EMPTY="-"; OK="ok"; ERR="x"; WARN="!"; DOT="-" ;;
esac

banner() {
  printf '%s' "$CYAN"
  cat <<'LOGO'
     _  _   __   __                             _
  __| |(_) / _| / _|__      __  __ _  _ __   __| |
 / _` || || |_ | |_ \ \ /\ / / / _` || '__| / _` |
| (_| || ||  _||  _| \ V  V / | (_| || |   | (_| |
 \__,_||_||_|  |_|    \_/\_/   \__,_||_|    \__,_|
LOGO
  printf '%s\n' "$RESET"
  printf '  %sSecurity scanner for pull requests%s %s%s installer%s\n\n' "$BOLD" "$RESET" "$DIM" "$DOT" "$RESET"
}

step() { printf '%s[%s/%s]%s %s%s%s\n' "$DIM" "$1" "$STEPS" "$RESET" "$BOLD" "$2" "$RESET"; }
info() { printf '      %s%-10s%s %s\n' "$DIM" "$1" "$RESET" "$2"; }
warn() { printf '      %s%s %s%s\n' "$YELLOW" "$WARN" "$1" "$RESET"; }

fail() {
  show_cursor
  printf '\n%s%s %s%s\n' "$RED" "$ERR" "$1" "$RESET" >&2
  [ $# -gt 1 ] && printf '  %s\n' "$2" >&2
  exit 1
}

hide_cursor() { [ "$INTERACTIVE" = 1 ] && printf '\033[?25l' || true; }
show_cursor() { [ "$INTERACTIVE" = 1 ] && printf '\033[?25h' || true; }

TMP=""
CURL_PID=""
cleanup() {
  [ -n "$CURL_PID" ] && kill "$CURL_PID" 2>/dev/null || true
  [ -n "$TMP" ] && rm -rf "$TMP"
  show_cursor
}
trap cleanup EXIT
trap 'printf "\n"; fail "Interrupted."' INT TERM

human() { # bytes → "61.3 MB"
  awk -v b="$1" 'BEGIN {
    split("B KB MB GB", u, " "); i = 1
    while (b >= 1024 && i < 4) { b /= 1024; i++ }
    printf (i == 1 ? "%d %s" : "%.1f %s"), b, u[i]
  }'
}

# "$HOME/.local/bin" → "~/.local/bin" for display
pretty() { case "$1" in "$HOME"/*) printf '~/%s' "${1#"$HOME"/}" ;; *) printf '%s' "$1" ;; esac; }

file_size() { if [ -f "$1" ]; then wc -c <"$1" | tr -d ' '; else echo 0; fi; }

need() { command -v "$1" >/dev/null 2>&1 || fail "'$1' is required but was not found." "Install it and run the installer again."; }

# ------------------------------------------------------------------ steps

detect_platform() {
  os=$(uname -s)
  arch=$(uname -m)
  case "$os" in
    Darwin)
      OS=darwin
      OS_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
      # An x86_64 shell under Rosetta on Apple Silicon should still get the native binary.
      if [ "$arch" = x86_64 ] && [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" = 1 ]; then arch=arm64; fi
      ;;
    Linux)
      OS=linux
      OS_NAME=$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-Linux}" || echo Linux)
      if ldd --version 2>&1 | grep -qi musl; then
        fail "musl-based Linux (e.g. Alpine) is not supported yet." "Use a glibc image such as debian:stable-slim, or run from source with Bun."
      fi
      ;;
    MINGW* | MSYS* | CYGWIN*)
      fail "On Windows, use the PowerShell installer:" "irm https://github.com/$REPO/releases/latest/download/install.ps1 | iex"
      ;;
    *) fail "Unsupported operating system: $os" ;;
  esac
  case "$arch" in
    x86_64 | amd64) ARCH=x64 ;;
    arm64 | aarch64) ARCH=arm64 ;;
    *) fail "Unsupported architecture: $arch" ;;
  esac
  ASSET="diffward-$OS-$ARCH"
}

resolve_version() {
  if [ -n "${DIFFWARD_VERSION:-}" ]; then
    VERSION="$DIFFWARD_VERSION"
    case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
    VERSION_NOTE="pinned"
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  else
    location=$(curl -fsSI "https://github.com/$REPO/releases/latest" | tr -d '\r' | awk 'tolower($1) == "location:" { print $2 }' | tail -n 1)
    VERSION=${location##*/}
    [ -n "$VERSION" ] || fail "Could not find the latest release." "Check your connection, or set DIFFWARD_VERSION=v0.2.0."
    VERSION_NOTE="latest"
    BASE="https://github.com/$REPO/releases/download/$VERSION"
  fi
}

current_version() {
  if [ -x "$INSTALL_DIR/diffward" ]; then "$INSTALL_DIR/diffward" --version 2>/dev/null || true; fi
}

draw_bar() { # done total elapsed_seconds
  done_b=$1; total=$2; elapsed=$3
  width=30
  if [ "$total" -gt 0 ]; then
    pct=$((done_b * 100 / total)); [ "$pct" -gt 100 ] && pct=100
    filled=$((pct * width / 100))
  else
    pct=0; filled=0
  fi
  bar=""
  i=0; while [ $i -lt $filled ]; do bar="$bar$FULL"; i=$((i + 1)); done
  rest=""
  while [ $i -lt $width ]; do rest="$rest$EMPTY"; i=$((i + 1)); done
  speed=""
  if [ "$elapsed" -gt 0 ]; then speed="  $(human $((done_b / elapsed)))/s"; fi
  if [ "$total" -gt 0 ]; then
    printf '\r      %s%s%s%s%s %3d%%  %s / %s%s\033[K' "$GREEN" "$bar" "$DIM" "$rest" "$RESET" "$pct" "$(human "$done_b")" "$(human "$total")" "$speed"
  else
    printf '\r      %s  %s%s\033[K' "$(human "$done_b")" "downloaded" "$speed"
  fi
}

download() {
  url="$BASE/$ASSET"
  out="$TMP/$ASSET"
  headers=$(curl -fsIL "$url" 2>/dev/null) ||
    fail "$ASSET is not published for $VERSION." "Available releases: https://github.com/$REPO/releases"
  total=$(printf '%s\n' "$headers" | tr -d '\r' | awk 'tolower($1) == "content-length:" { n = $2 } END { print n + 0 }')
  info "Package" "$ASSET ($(human "$total"))"

  start=$(date +%s)
  curl -fsL -o "$out" "$url" &
  CURL_PID=$!

  if [ "$INTERACTIVE" = 1 ]; then
    hide_cursor
    while kill -0 "$CURL_PID" 2>/dev/null; do
      size=$(file_size "$out")
      draw_bar "${size:-0}" "$total" $(($(date +%s) - start))
      sleep 0.1
    done
  else
    # CI logs: a line every 25% instead of a redrawn bar.
    next=25
    while kill -0 "$CURL_PID" 2>/dev/null; do
      size=$(file_size "$out")
      if [ "$total" -gt 0 ] && [ $((${size:-0} * 100 / total)) -ge $next ] && [ $next -lt 100 ]; then
        info "" "$next% ($(human "${size:-0}") / $(human "$total"))"
        next=$((next + 25))
      fi
      sleep 1
    done
  fi

  status=0
  wait "$CURL_PID" || status=$?
  CURL_PID=""
  [ "$status" -eq 0 ] || { [ "$INTERACTIVE" = 1 ] && printf '\n'; fail "Download failed (curl exit $status)." "$url"; }

  size=$(wc -c <"$out" | tr -d ' ')
  elapsed=$(($(date +%s) - start))
  if [ "$INTERACTIVE" = 1 ]; then
    draw_bar "$size" "${total:-$size}" "$elapsed"
    printf '\n'
    show_cursor
  fi
  [ "$total" -eq 0 ] || [ "$size" -eq "$total" ] || fail "Incomplete download: got $(human "$size") of $(human "$total")."
  info "Done" "$(human "$size") in ${elapsed}s"
}

verify() {
  sums="$TMP/SHA256SUMS"
  curl -fsSL -o "$sums" "$BASE/SHA256SUMS" || fail "Could not download SHA256SUMS for $VERSION."
  expected=$(awk -v a="$ASSET" '$2 == a { print $1 }' "$sums")
  [ -n "$expected" ] || fail "No checksum for $ASSET in SHA256SUMS."
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$TMP/$ASSET" | awk '{ print $1 }')
  else
    actual=$(shasum -a 256 "$TMP/$ASSET" | awk '{ print $1 }')
  fi
  [ "$actual" = "$expected" ] || fail "Checksum mismatch: the download is corrupted or was tampered with." "expected $expected, got $actual"
  SHORT_SUM="$(printf '%s' "$actual" | cut -c1-8)…$(printf '%s' "$actual" | cut -c57-64)"
  info "SHA-256" "$SHORT_SUM ${GREEN}$OK${RESET}"
}

install_binary() {
  mkdir -p "$INSTALL_DIR" || fail "Cannot create $INSTALL_DIR." "Set DIFFWARD_INSTALL_DIR to a writable directory."
  INSTALL_DIR=$(cd "$INSTALL_DIR" && pwd) # absolute, for the PATH hint
  chmod +x "$TMP/$ASSET"
  # Gatekeeper blocks binaries downloaded by a browser; curl doesn't set the flag, but be safe.
  [ "$OS" = darwin ] && xattr -d com.apple.quarantine "$TMP/$ASSET" 2>/dev/null || true
  mv -f "$TMP/$ASSET" "$INSTALL_DIR/diffward" || fail "Cannot write to $INSTALL_DIR." "Set DIFFWARD_INSTALL_DIR to a writable directory."
  INSTALLED=$("$INSTALL_DIR/diffward" --version 2>/dev/null) || fail "The installed binary does not run on this system."
  info "Location" "$(pretty "$INSTALL_DIR/diffward")"
}

path_hint() {
  case ":$PATH:" in *":$INSTALL_DIR:"*) return 0 ;; esac
  case "${SHELL:-}" in
    */zsh) rc="~/.zshrc"; line="export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    */bash) rc="~/.bashrc"; line="export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    */fish) rc="fish"; line="fish_add_path $INSTALL_DIR" ;;
    *) rc="your shell profile"; line="export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac
  printf '\n  %s%s %s is not on your PATH.%s Add it (%s):\n' "$YELLOW" "$WARN" "$(pretty "$INSTALL_DIR")" "$RESET" "$rc"
  printf '      %s\n' "$line"
}

summary() {
  printf '\n  %s%s diffward %s installed%s' "$GREEN$BOLD" "$OK" "$INSTALLED" "$RESET"
  [ -n "$PREVIOUS" ] && [ "$PREVIOUS" != "$INSTALLED" ] && printf ' %s(was %s)%s' "$DIM" "$PREVIOUS" "$RESET"
  printf '\n'
  path_hint
  printf '\n  %sNext steps%s\n' "$BOLD" "$RESET"
  printf '      %-32s %s\n' "diffward --diff origin/main" "${DIM}scan what your branch changes${RESET}"
  printf '      %-32s %s\n' "diffward" "${DIM}scan the whole repository${RESET}"
  printf '      %-32s %s\n' "diffward baseline" "${DIM}adopt on an existing project${RESET}"
  printf '      %-32s %s\n' "diffward --help" "${DIM}all options${RESET}"
  printf '\n  %sDocs: https://github.com/%s%s\n\n' "$DIM" "$REPO" "$RESET"
}

# ------------------------------------------------------------------ main

need curl
need uname
banner

step 1 "Detecting your system"
detect_platform
resolve_version
PREVIOUS=$(current_version)
info "System" "$OS_NAME $DOT $ARCH"
info "Version" "$VERSION ($VERSION_NOTE)"
if [ -n "$PREVIOUS" ]; then
  info "Installed" "$PREVIOUS"
  if [ "v$PREVIOUS" = "$VERSION" ] && [ "${DIFFWARD_FORCE:-0}" != 1 ]; then
    printf '\n  %s%s diffward %s is already installed and up to date.%s\n' "$GREEN" "$OK" "$PREVIOUS" "$RESET"
    printf '  %sDIFFWARD_FORCE=1 reinstalls it.%s\n\n' "$DIM" "$RESET"
    exit 0
  fi
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t diffward)

printf '\n'
step 2 "Downloading"
download

printf '\n'
step 3 "Verifying"
verify

printf '\n'
step 4 "Installing"
install_binary

summary
