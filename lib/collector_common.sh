#!/usr/bin/env bash
# collector_common.sh — shared helpers for build_collector.sh,
# build_collector_macos.sh, and the version check in .github/workflows/ci.yml.
#
# Source this file (`. lib/collector_common.sh`); it only DEFINES functions and
# has no side effects, so it is safe to source under `set -euo pipefail`.

# Fetch a URL, retrying until the response body is valid JSON.
# Prints the JSON to stdout; returns non-zero after exhausting retries.
fetch_with_retry() {
  local url="$1"
  local max_retries=3 retry_delay=2 attempt=1 response
  while [ "$attempt" -le "$max_retries" ]; do
    if [ "$attempt" -gt 1 ]; then
      echo "Fetching from GitHub API (attempt $attempt/$max_retries)..." >&2
    fi
    response=$(curl -s -L "$url" || true)
    if echo "$response" | jq -e . >/dev/null 2>&1; then
      echo "$response"
      return 0
    fi
    if [ "$attempt" -lt "$max_retries" ]; then
      echo "Request failed, retrying in ${retry_delay}s..." >&2
      sleep "$retry_delay"
      retry_delay=$((retry_delay * 2))  # Exponential backoff
    fi
    attempt=$((attempt + 1))
  done
  echo "Error: Failed to fetch valid JSON from GitHub API after $max_retries attempts" >&2
  echo "Debug - Last response received: ${response:0:200}..." >&2
  return 1
}

# Download $1 to file $2 with retries; returns non-zero after exhausting retries.
download_with_retry() {
  local url="$1" output="$2"
  local max_retries=3 retry_delay=2 attempt=1
  while [ "$attempt" -le "$max_retries" ]; do
    if [ "$attempt" -gt 1 ]; then
      echo "Downloading binary (attempt $attempt/$max_retries)..." >&2
    fi
    if curl -L "$url" -o "$output" --fail --silent --show-error; then
      echo "Download successful"
      return 0
    fi
    if [ "$attempt" -lt "$max_retries" ]; then
      echo "Download failed, retrying in ${retry_delay}s..." >&2
      rm -f "$output"  # Clean up partial download
      sleep "$retry_delay"
      retry_delay=$((retry_delay * 2))  # Exponential backoff
    fi
    attempt=$((attempt + 1))
  done
  echo "Error: Failed to download binary after $max_retries attempts" >&2
  return 1
}

# Print the {name,url} JSON object of the highest *numeric*-version Velociraptor
# release asset matching arch suffix $2 (e.g. "linux-amd64", "darwin-arm64") in
# the releases JSON $1. Sorting by parsed numeric version (not lexicographically)
# means v0.76.10 correctly outranks v0.76.5 — the "latest" release contains many
# patch versions as separate assets. Returns {"name":null,"url":null} if none
# match, so callers can guard on a null/empty url.
select_velociraptor_asset() {
  local json="$1" arch="$2"
  echo "$json" | jq -c --arg arch "$arch" '
    [.assets[]
     | select(.name | test("velociraptor-v[0-9.]+-" + $arch + "$"))
     | {name: .name,
        url: .browser_download_url,
        ver: (.name | capture("velociraptor-v(?<v>[0-9]+(\\.[0-9]+)*)-" + $arch + "$").v
                    | split(".") | map(tonumber))}]
    | sort_by(.ver) | last | {name, url}'
}

# Print the download URL of the asset whose name is exactly $2 in releases JSON
# $1; empty if absent. Used to pin a binary to one exact, known version.
asset_url_by_name() {
  local json="$1" name="$2"
  echo "$json" | jq -r --arg n "$name" '.assets[] | select(.name == $n) | .browser_download_url'
}

# Extract the content-identifying part of an nginx/S3-style ETag. These servers
# emit ETags of the form "<mtime-hex>-<content-length-hex>" (optionally with a
# content-coding suffix like "-gzip"); the mtime prefix can differ between CDN
# edge nodes (or after a no-op touch) for byte-identical content, which would
# otherwise trip change-detection and the download race-guard with a false
# positive. We return the content-length field — the SECOND hyphen-delimited
# field — so a trailing "-gzip" (or any extra suffix) does not shift which field
# is read. With no hyphen the whole de-quoted value is returned so a non-standard
# ETag still compares exactly.
etag_content_id() {
  local etag="${1#W/}"   # drop weak-validator prefix
  etag="${etag//\"/}"    # drop quotes
  local rest="${etag#*-}"     # strip the mtime field (everything up to first '-')
  printf '%s' "${rest%%-*}"   # keep the content-length field (up to the next '-')
}

# Detect whether an artifact was republished (swapped for different content)
# between the pre-download HEAD — whose ETag is $3 — and now, i.e. a release
# raced our build. download_with_retry already guarantees the bytes are complete
# (curl --fail errors on a short read vs Content-Length and retries), so this
# only re-reads the ETag and compares its content-length field, which is
# mtime-wobble tolerant (see etag_content_id). A same-byte-length content swap
# cannot be detected from HTTP metadata (no server content hash); the separate
# stored-SHA256 reuse check is the only content-level guard. If the post-download
# HEAD yields no ETag (transient/redirect), degrade gracefully rather than fail.
# The trailing `|| true` keeps the no-match grep from aborting under pipefail.
# Args: <url> <file> <pre_download_etag> <label>. rm's <file> and exits 1 on a race.
verify_download_not_raced() {
  local url="$1" file="$2" pre_etag="$3" label="$4"
  local post_etag
  post_etag=$(curl -sI --fail --max-time 30 "$url" 2>/dev/null | grep -im1 '^etag:' | tr -d '\r' | sed 's/^[Ee][Tt][Aa][Gg]: *//' || true)
  if [ -z "$post_etag" ]; then
    echo "Warning: could not re-fetch $label ETag after download; relying on the completed download + SHA256 checks" >&2
    return 0
  fi
  if [ "$(etag_content_id "$pre_etag")" != "$(etag_content_id "$post_etag")" ]; then
    echo "Error: $label content changed during download (race condition detected)" >&2
    echo "  Pre-download ETag:  $pre_etag" >&2
    echo "  Post-download ETag: $post_etag" >&2
    echo "Please re-run the build to get the latest version." >&2
    rm -f "$file"
    exit 1
  fi
  echo "$label download verified: content unchanged during download"
}

# Verify a built collector is a real self-contained binary, not the ~100KB
# BYO-binary shell stub the offline-collector builder emits when an embedded tool
# fails to resolve. Requires BOTH a sane size (>= 10MB; real collectors embed a
# 60-85MB velociraptor binary) AND a compiled-executable file type (ELF/Mach-O/
# PE) — an allowlist, so a stub classified as a script, text, "data", or "empty"
# is rejected regardless of `file`'s exact wording. Exits 1 on failure.
verify_collector_not_stub() {
  local f="$1"
  local min_bytes=10000000
  local size ftype
  size=$(wc -c < "$f")
  ftype=$(file -b "$f")
  if [ "$size" -lt "$min_bytes" ]; then
    echo "Error: $f is $size bytes (< $min_bytes) — looks like a BYO-binary stub, not a self-contained collector" >&2
    exit 1
  fi
  case "$ftype" in
    *ELF*|*Mach-O*|*PE32*)
      echo "Verified self-contained collector: $f ($size bytes, $ftype)" ;;
    *)
      echo "Error: $f is '$ftype' — expected a compiled ELF/Mach-O/PE executable, not a script/text/data (stub?)" >&2
      exit 1 ;;
  esac
}
