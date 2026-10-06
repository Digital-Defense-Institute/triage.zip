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

# Select the highest numeric version for an exact architecture, accepting raw
# and gzip releases. Optional $3 pins the exact version (never silently falls
# back to another patch). Prefer gzip deterministically when both forms exist.
# Missing matches retain null fields so existing URL guards keep working.
select_velociraptor_asset() {
  local json="$1" arch="$2" version="${3:-}"
  printf '%s\n' "$json" | jq -c --arg arch "$arch" --arg version "$version" '
    [.assets[]
     | . as $asset
     | (.name | capture("^velociraptor-v(?<v>[0-9]+(\\.[0-9]+)*)-(?<arch>[a-z0-9-]+)(?<gz>\\.gz)?$")) as $match
     | select($match.arch == $arch)
     | select($version == "" or $match.v == $version)
     | {name: $asset.name, url: $asset.browser_download_url,
        version: $match.v, size: $asset.size, digest: $asset.digest,
        ver: ($match.v | split(".") | map(tonumber)),
        compressed: ($match.gz != null)}]
    | sort_by(.ver, .compressed) | last | {name, url, version, size, digest}'
}

# Exact-name lookup retained for callers that already know the full asset name.
asset_url_by_name() {
  local json="$1" name="$2"
  echo "$json" | jq -r --arg n "$name" '.assets[] | select(.name == $n) | .browser_download_url'
}

# Validate transport bytes before decompression, then reject non-executables.
# The GitHub SHA256 digest is checked when supplied (older releases omit it).
# Use a private temporary directory beside the destination and publish only a
# fully validated binary, leaving an existing destination intact on any failure.
download_velociraptor_asset() (
  local asset="$1" output="$2" name url size digest tmp actual ftype
  name=$(printf '%s' "$asset" | jq -er '.name') || return 1
  url=$(printf '%s' "$asset" | jq -er '.url | select(length > 0)') || return 1
  size=$(printf '%s' "$asset" | jq -r '.size // empty') || return 1
  digest=$(printf '%s' "$asset" | jq -r '.digest // empty') || return 1
  tmp=$(mktemp -d "${output}.download.XXXXXX") || return 1
  trap 'rm -rf "$tmp"' EXIT
  download_with_retry "$url" "$tmp/asset" || return 1
  if [ ! -s "$tmp/asset" ]; then
    echo "Error: empty Velociraptor download: $name" >&2
    return 1
  fi
  if [ -n "$size" ] && [ "$(wc -c < "$tmp/asset" | tr -d ' ')" != "$size" ]; then
    echo "Error: Velociraptor download size mismatch: $name" >&2
    return 1
  fi
  if [ -n "$digest" ]; then
    case "$digest" in
      sha256:*) ;;
      *) echo "Error: unsupported asset digest: $digest" >&2; return 1 ;;
    esac
    if command -v sha256sum >/dev/null 2>&1; then
      actual=$(sha256sum "$tmp/asset") || return 1
    else
      actual=$(shasum -a 256 "$tmp/asset") || return 1
    fi
    if [ "${actual%% *}" != "${digest#sha256:}" ]; then
      echo "Error: Velociraptor download SHA256 mismatch: $name" >&2
      return 1
    fi
  fi
  case "$name" in
    *.gz) gzip -dc "$tmp/asset" > "$tmp/binary" || return 1 ;;
    *) mv "$tmp/asset" "$tmp/binary" || return 1 ;;
  esac
  ftype=$(file -b "$tmp/binary") || return 1
  case "$name:$ftype" in
    *-linux-amd64*:ELF*x86-64*|*-darwin-amd64*:Mach-O*x86_64*|*-darwin-arm64*:Mach-O*arm64*) ;;
    *) echo "Error: unexpected executable type for $name: $ftype" >&2; return 1 ;;
  esac
  chmod +x "$tmp/binary" || return 1
  mv "$tmp/binary" "$output" || return 1
)

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
# mtime-wobble tolerant (see etag_content_id). This is best-effort: a republish
# that keeps the exact byte length is not detectable from HTTP metadata (no
# server content hash), and the stored-SHA256 check elsewhere only fires when the
# ETag is unchanged across builds, so it does not backstop a mid-build republish
# either. If the post-download HEAD yields no ETag (transient/redirect), degrade
# gracefully rather than fail.
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

# Ad-hoc code-sign a macOS (Mach-O) collector so modern macOS will run it.
# Velociraptor's offline-collector builder embeds the collection config by
# APPENDING it to the darwin velociraptor binary, which invalidates the binary's
# code signature. macOS (Sequoia / 26+) then SIGKILLs the collector on launch
# ("zsh: killed"). An ad-hoc signature (no certificate) restores a valid
# signature so it runs. NOTE: ad-hoc is NOT notarization — a browser download is
# still Gatekeeper-quarantined and needs `xattr -d com.apple.quarantine` first.
# Prefers Apple's codesign (macOS host); on Linux CI uses rcodesign, which can
# sign Mach-O cross-platform (`./rcodesign` if downloaded into the workspace, or
# on PATH). Signing is required: returns non-zero if no signer is available.
adhoc_sign_macos() {
  local file="$1"
  if command -v codesign >/dev/null 2>&1; then
    codesign --force --sign - "$file" || return 1
  elif [ -x ./rcodesign ]; then
    ./rcodesign sign "$file" || return 1
  elif command -v rcodesign >/dev/null 2>&1; then
    rcodesign sign "$file" || return 1
  else
    echo "Error: no ad-hoc signing tool (codesign or rcodesign) found to sign $file" >&2
    return 1
  fi
  echo "Ad-hoc signed: $file"
}
