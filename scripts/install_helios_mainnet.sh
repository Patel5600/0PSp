#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly VERSION="0.12.0"
readonly URL="https://github.com/a16z/helios/releases/download/$VERSION/helios_linux_amd64.tar.gz"
readonly ARCHIVE_SHA256="dd2746b11323f8f4a4e4613891b275148f34963bf4912cab79a34316a02a94b4"
readonly DEST_DIR="$HOME/.local/bin"
readonly DEST="$DEST_DIR/helios-$VERSION"

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
[[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]] || {
  echo "This pinned installer supports Linux x86_64 (including x86_64 WSL) only." >&2
  exit 1
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl --fail --location --silent --show-error --retry 3 "$URL" -o "$tmp/helios.tgz"
printf '%s  %s\n' "$ARCHIVE_SHA256" "$tmp/helios.tgz" | sha256sum --check --status || {
  echo "Helios release archive SHA-256 mismatch; refusing extraction." >&2
  exit 1
}

tar -tzf "$tmp/helios.tgz" | awk '
  {
    path=$0
    sub(/^\.\//, "", path)
    if (path == "helios" || path ~ /\/helios$/) {
      if (path ~ /^\// || path ~ /(^|\/)\.\.(\/|$)/) exit 9
      print $0
    }
  }
' > "$tmp/matches"
match_count="$(wc -l < "$tmp/matches" | tr -d ' ')"
[[ "$match_count" == "1" ]] || {
  echo "Expected exactly one safe executable named helios in the pinned archive." >&2
  exit 1
}
entry="$(cat "$tmp/matches")"
tar -xOzf "$tmp/helios.tgz" "$entry" > "$tmp/helios"
[[ -s "$tmp/helios" ]] || { echo "Extracted binary is empty." >&2; exit 1; }
chmod 0700 "$tmp/helios"
version_output="$("$tmp/helios" --version 2>&1)" || {
  echo "Pinned executable failed its --version check." >&2
  exit 1
}
[[ "$version_output" == *"$VERSION"* ]] || {
  echo "Unexpected Helios version output: $version_output" >&2
  exit 1
}

mkdir -p "$DEST_DIR"
install -m 0755 "$tmp/helios" "$DEST"
echo "Installed $DEST"
echo "Version: $version_output"
echo "Executable SHA-256 (pin this out of band in HeliosMainnetConfig.binary_sha256):"
sha256sum "$DEST"
echo "Archive SHA-256 was verified before extraction. This does not replace an independent review of the light-client implementation or the source of the weak-subjectivity checkpoint."
