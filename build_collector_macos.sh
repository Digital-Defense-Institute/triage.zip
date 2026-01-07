#!/bin/bash
set -euo pipefail

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

# Download Velociraptor binary and make it executable
download_with_retry "$download_url" "./velociraptor" || exit 1
chmod +x ./velociraptor

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

# Capture build timestamp in ISO 8601 UTC format
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Write metadata JSON using jq for proper escaping (prevents JSON injection)
echo "Writing build metadata..."
if [ -n "${TRIAGE_ETAG:-}" ]; then
  jq -n --arg ver "$velociraptor_version" --arg etag "$TRIAGE_ETAG" --arg sha "$ARTIFACT_SHA256" --arg ts "$BUILD_TIMESTAMP" \
    '{velociraptor_version: $ver, triage_targets_etag: $etag, triage_targets_sha256: $sha, last_build_timestamp: $ts}' > data/velociraptor-version.json
else
  jq -n --arg ver "$velociraptor_version" --arg sha "$ARTIFACT_SHA256" --arg ts "$BUILD_TIMESTAMP" \
    '{velociraptor_version: $ver, triage_targets_sha256: $sha, last_build_timestamp: $ts}' > data/velociraptor-version.json
fi
echo "Metadata written to data/velociraptor-version.json"

# Run the collector command
./velociraptor collector --datastore ./datastore/ ./config/spec.yaml
