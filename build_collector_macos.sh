#!/bin/bash
set -euo pipefail

# NOTE: This script downloads darwin-amd64 which requires Rosetta on Apple
# Silicon. It also depends on the darwin build matching the linux-amd64 release
# version — if Velocidex publishes a new linux build before the darwin build
# (as happened with 0.75.6), the older darwin binary may lack VQL features
# (e.g. parse_yaml schema support) that the collector command requires.

# Check prerequisites
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed" >&2; exit 1; }

echo "Starting build_collector.sh (macOS version)..."

# Function to fetch with retries
fetch_with_retry() {
  local url="$1"
  local max_retries=3
  local retry_delay=2
  local attempt=1

  while [ $attempt -le $max_retries ]; do
    if [ $attempt -gt 1 ]; then
      echo "Fetching from GitHub API (attempt $attempt/$max_retries)..." >&2
    fi
    response=$(curl -s -L "$url" || true)

    # Check if we got valid JSON
    if echo "$response" | jq -e . >/dev/null 2>&1; then
      echo "$response"
      return 0
    fi

    if [ $attempt -lt $max_retries ]; then
      echo "Request failed, retrying in ${retry_delay}s..." >&2
      sleep $retry_delay
      retry_delay=$((retry_delay * 2))  # Exponential backoff
    fi

    attempt=$((attempt + 1))
  done

  echo "Error: Failed to fetch valid JSON from GitHub API after $max_retries attempts" >&2
  echo "Debug - Last response received: ${response:0:200}..." >&2
  return 1
}

# Fetch the latest Velociraptor release information from GitHub API
response=$(fetch_with_retry "https://api.github.com/repos/Velocidex/velociraptor/releases/latest") || exit 1

# Check if response is empty
if [ -z "$response" ]; then
  echo "Error: Empty response from GitHub API" >&2
  exit 1
fi

# Identify download URL and derive version from asset name
asset_info=$(echo "$response" | jq -r '[.assets[] | select(.name | test("velociraptor-.*-darwin-amd64$")) | {name: .name, url: .browser_download_url}] | sort_by(.name) | last')
download_url=$(echo "$asset_info" | jq -r '.url')
asset_name=$(echo "$asset_info" | jq -r '.name')

if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
  echo "Error: Could not find a macOS binary in the latest release" >&2
  echo "Debug - Available assets:" >&2
  echo "$response" | jq -r '.assets[].name' >&2
  exit 1
fi

binary_version=$(echo "$asset_name" | sed -n 's/.*velociraptor-v\([0-9.]*\)-darwin-amd64$/\1/p')
velociraptor_version=${binary_version:-$(echo "$response" | jq -r '.tag_name' | sed 's/^v//')}

if [ -z "$velociraptor_version" ] || [ "$velociraptor_version" == "null" ]; then
  echo "Error: Unable to determine Velociraptor version from asset metadata" >&2
  exit 1
fi

echo "Velociraptor release version: $velociraptor_version"

# Persist and compare versions
stored_version="unknown"
if [ -f data/velociraptor-version.json ]; then
  stored_version=$(jq -r '.velociraptor_version // "unknown"' data/velociraptor-version.json 2>/dev/null || echo "unknown")
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "VELO_VERSION=$velociraptor_version" >> "$GITHUB_ENV"
fi

if [ "$stored_version" = "$velociraptor_version" ] && [ -n "${SKIP_IF_VERSION_UNCHANGED:-}" ]; then
  echo "Velociraptor version unchanged ($velociraptor_version); skipping build."
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "VELO_VERSION_CHANGED=false" >> "$GITHUB_ENV"
  fi
  exit 0
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "VELO_VERSION_CHANGED=true" >> "$GITHUB_ENV"
fi

# Create data directory for metadata (JSON written after artifact download)
mkdir -p data

echo "Downloading Velociraptor binary from: $download_url"

# Download with retries
download_with_retry() {
  local url="$1"
  local output="$2"
  local max_retries=3
  local retry_delay=2
  local attempt=1

  while [ $attempt -le $max_retries ]; do
    if [ $attempt -gt 1 ]; then
      echo "Downloading binary (attempt $attempt/$max_retries)..." >&2
    fi
    if curl -L "$url" -o "$output" --fail --silent --show-error; then
      echo "Download successful"
      return 0
    fi

    if [ $attempt -lt $max_retries ]; then
      echo "Download failed, retrying in ${retry_delay}s..." >&2
      rm -f "$output"  # Clean up partial download
      sleep $retry_delay
      retry_delay=$((retry_delay * 2))  # Exponential backoff
    fi

    attempt=$((attempt + 1))
  done

  echo "Error: Failed to download binary after $max_retries attempts" >&2
  return 1
}

# Download Velociraptor binary and make it executable (darwin-amd64 host binary)
download_with_retry "$download_url" "./velociraptor" || exit 1
chmod +x ./velociraptor

# Also fetch the darwin-arm64 binary so we can build a self-contained Apple
# Silicon collector. Both macOS specs resolve to a single "VelociraptorCollector"
# tool with no default URL, so each arch's binary must be registered before its
# build or the collector becomes a tiny BYO-binary shell stub.
# Pin to the EXACT host version ($velociraptor_version, derived from the
# darwin-amd64 host binary) via an exact name match rather than a lexicographic
# sort_by(.name)|last — this picks the right patch and fails loud on per-arch
# version skew instead of embedding a mismatched, version-bound binary.
darwin_arm64_url=$(echo "$response" | jq -r --arg n "velociraptor-v${velociraptor_version}-darwin-arm64" '.assets[] | select(.name == $n) | .browser_download_url')
if [ -z "$darwin_arm64_url" ] || [ "$darwin_arm64_url" == "null" ]; then
  echo "Error: darwin-arm64 binary for v${velociraptor_version} not found in the latest release (host is darwin-amd64 v${velociraptor_version}; per-arch version skew?)" >&2
  exit 1
fi
echo "Downloading Velociraptor darwin-arm64 binary..."
download_with_retry "$darwin_arm64_url" "./velociraptor_darwin_arm64" || exit 1

# Download and extract Windows.Triage.Targets artifact
mkdir -p ./datastore/artifact_definitions/Windows/Triage
ARTIFACT_URL="https://triage.velocidex.com/artifacts/Windows.Triage.Targets.zip"
echo "Downloading Windows.Triage.Targets artifact..."
download_with_retry "$ARTIFACT_URL" "Windows.Triage.Targets.zip" || exit 1

# Compute SHA256 hash of downloaded artifact for integrity verification (macOS uses shasum)
ARTIFACT_SHA256=$(shasum -a 256 Windows.Triage.Targets.zip | cut -d' ' -f1)
echo "Windows.Triage.Targets.zip SHA256: $ARTIFACT_SHA256"

# Re-fetch ETag after download to detect race conditions (artifact changed during build)
if [ -n "${TRIAGE_ETAG:-}" ]; then
  POST_DOWNLOAD_HEADERS=$(curl -sI --fail --max-time 30 "$ARTIFACT_URL" 2>/dev/null || true)
  POST_DOWNLOAD_ETAG=$(echo "$POST_DOWNLOAD_HEADERS" | grep -im1 "^etag:" | tr -d '\r' | sed 's/^[Ee][Tt][Aa][Gg]: *//')

  # Only compare if we successfully retrieved the post-download ETag
  if [ -z "$POST_DOWNLOAD_ETAG" ]; then
    echo "Warning: Could not verify ETag after download (HEAD request returned no ETag)" >&2
    echo "Continuing with SHA256 verification as fallback..." >&2
  elif [ "$TRIAGE_ETAG" != "$POST_DOWNLOAD_ETAG" ]; then
    echo "Error: Artifact ETag changed during download (race condition detected)" >&2
    echo "  Pre-download ETag:  $TRIAGE_ETAG" >&2
    echo "  Post-download ETag: $POST_DOWNLOAD_ETAG" >&2
    echo "This indicates the artifact was updated while we were building." >&2
    echo "Please re-run the build to get the latest version." >&2
    rm -f Windows.Triage.Targets.zip
    exit 1
  else
    echo "ETag verified: artifact unchanged during download"
  fi
fi

# Verify hash against previously stored value (detect tampering if ETag reused)
if [ -f data/velociraptor-version.json ]; then
  STORED_SHA256=$(jq -r '.triage_targets_sha256 // ""' data/velociraptor-version.json 2>/dev/null || echo "")
  STORED_ETAG=$(jq -r '.triage_targets_etag // ""' data/velociraptor-version.json 2>/dev/null || echo "")
  if [ -n "$STORED_SHA256" ] && [ -n "$STORED_ETAG" ] && [ "$STORED_ETAG" = "${TRIAGE_ETAG:-}" ]; then
    # Same ETag but different hash = potential tampering
    if [ "$STORED_SHA256" != "$ARTIFACT_SHA256" ]; then
      echo "SECURITY WARNING: Hash mismatch detected!" >&2
      echo "  ETag is unchanged: $STORED_ETAG" >&2
      echo "  Previous SHA256:   $STORED_SHA256" >&2
      echo "  Current SHA256:    $ARTIFACT_SHA256" >&2
      echo "This could indicate artifact tampering or cache inconsistency." >&2
      echo "Failing build for manual investigation." >&2
      rm -f Windows.Triage.Targets.zip
      exit 1
    fi
    echo "Hash verified: matches previously stored value"
  fi
fi

unzip -o Windows.Triage.Targets.zip -d ./datastore/artifact_definitions/Windows/Triage
rm Windows.Triage.Targets.zip

# Download and extract Linux.Triage.UAC artifact
mkdir -p ./datastore/artifact_definitions/Linux/Triage
LINUX_ARTIFACT_URL="https://triage.velocidex.com/artifacts/Linux.Triage.UAC.zip"
echo "Downloading Linux.Triage.UAC artifact..."
download_with_retry "$LINUX_ARTIFACT_URL" "Linux.Triage.UAC.zip" || exit 1

# Compute SHA256 hash of downloaded Linux artifact for integrity verification (macOS uses shasum)
LINUX_ARTIFACT_SHA256=$(shasum -a 256 Linux.Triage.UAC.zip | cut -d' ' -f1)
echo "Linux.Triage.UAC.zip SHA256: $LINUX_ARTIFACT_SHA256"

unzip -o Linux.Triage.UAC.zip -d ./datastore/artifact_definitions/Linux/Triage
rm Linux.Triage.UAC.zip

# Capture build timestamp in ISO 8601 UTC format
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Write metadata JSON using jq for proper escaping (prevents JSON injection)
echo "Writing build metadata..."
jq -n --arg ver "$velociraptor_version" --arg sha "$ARTIFACT_SHA256" --arg linux_sha "$LINUX_ARTIFACT_SHA256" --arg ts "$BUILD_TIMESTAMP" \
  '{velociraptor_version: $ver, triage_targets_sha256: $sha, linux_triage_targets_sha256: $linux_sha, last_build_timestamp: $ts}' > data/velociraptor-version.json
echo "Metadata written to data/velociraptor-version.json"

# Build the Windows x64 collector
echo "Building Windows x64 collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec.yaml

# Build the Windows x86 (32-bit) collector using the same datastore
echo "Building Windows x86 collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec_x86.yaml

# Build the Linux collector using the same datastore
echo "Building Linux collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec_linux.yaml

# Embed the darwin velociraptor binary into each macOS collector. Both specs map
# to the single "VelociraptorCollector" tool, so register the matching arch's
# binary into the datastore inventory immediately before each build. "tools
# upload" works through a server config rather than --datastore, so generate a
# minimal config pointed at the same ./datastore the collector builds use.
# (./velociraptor is the darwin-amd64 host binary downloaded above.)
# A self-contained macOS collector embeds the ~60-70MB darwin binary. If the
# tool registration silently fails, the builder falls back to a ~100KB
# BYO-binary shell stub. Fail the build rather than ship a stub.
verify_collector_not_stub() {
  local f="$1"
  local min_bytes=10000000
  local size
  size=$(wc -c < "$f")
  if [ "$size" -lt "$min_bytes" ]; then
    echo "Error: $f is $size bytes (< $min_bytes) — looks like a BYO-binary stub, not a self-contained collector" >&2
    exit 1
  fi
  echo "Verified self-contained collector: $f ($size bytes)"
}

echo "Generating server config for darwin tool registration..."
./velociraptor config generate > server.config.yaml
DATASTORE_ABS="$(pwd)/datastore"
awk -v ds="$DATASTORE_ABS" '
  /^Datastore:/ { in_ds = 1 }
  in_ds && /^  location:/ { print "  location: " ds; next }
  in_ds && /^  filestore_directory:/ { print "  filestore_directory: " ds; next }
  /^[A-Za-z]/ && !/^Datastore:/ { in_ds = 0 }
  { print }
' server.config.yaml > server.config.yaml.tmp && mv server.config.yaml.tmp server.config.yaml

# Confirm the rewrite actually pointed the datastore at ./datastore, otherwise
# "tools upload" would target the default datastore and the build would silently
# emit a stub.
if ! grep -qF "location: ${DATASTORE_ABS}" server.config.yaml; then
  echo "Error: server.config.yaml Datastore was not repointed to ${DATASTORE_ABS} (velociraptor config format may have changed)" >&2
  exit 1
fi

# Build the macOS ARM64 collector (embed darwin-arm64 binary)
echo "Registering darwin-arm64 binary and building macOS ARM64 collector..."
./velociraptor --config server.config.yaml tools upload --name VelociraptorCollector --download ./velociraptor_darwin_arm64
./velociraptor collector --datastore ./datastore/ ./config/spec_macos_arm.yaml
verify_collector_not_stub ./datastore/Velociraptor_Triage_Collector_macOS_ARM

# Build the macOS x64 collector (re-point VelociraptorCollector to darwin-amd64)
echo "Registering darwin-amd64 binary and building macOS x64 collector..."
./velociraptor --config server.config.yaml tools upload --name VelociraptorCollector --download ./velociraptor
./velociraptor collector --datastore ./datastore/ ./config/spec_macos.yaml
verify_collector_not_stub ./datastore/Velociraptor_Triage_Collector_macOS
