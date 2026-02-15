#!/bin/bash
set -euo pipefail

echo "Starting build_collector.sh..."

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
asset_info=$(echo "$response" | jq -r '[.assets[] | select(.name | test("velociraptor-.*-linux-amd64$")) | {name: .name, url: .browser_download_url}] | sort_by(.name) | last')
download_url=$(echo "$asset_info" | jq -r '.url')
asset_name=$(echo "$asset_info" | jq -r '.name')

if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
  echo "Error: Could not find a Linux AMD64 binary in the latest release" >&2
  echo "Debug - Available assets:" >&2
  echo "$response" | jq -r '.assets[].name' >&2
  exit 1
fi

binary_version=$(echo "$asset_name" | sed -n 's/.*velociraptor-v\([0-9.]*\)-linux-amd64$/\1/p')
velociraptor_version=${binary_version:-$(echo "$response" | jq -r '.tag_name' | sed 's/^v//')}

if [ -z "$velociraptor_version" ] || [ "$velociraptor_version" == "null" ]; then
  echo "Error: Unable to determine Velociraptor version from asset metadata" >&2
  exit 1
fi

echo "Velociraptor release version: $velociraptor_version"

# Load previously stored version if available
stored_version="unknown"
if [ -f data/velociraptor-version.json ]; then
  stored_version=$(jq -r '.velociraptor_version // "unknown"' data/velociraptor-version.json 2>/dev/null || echo "unknown")
fi

if [ -n "${GITHUB_ENV:-}" ]; then
  echo "VELO_VERSION=$velociraptor_version" >> "$GITHUB_ENV"
fi

# Skip build only if Velociraptor version AND all triage targets are unchanged
if [ "$stored_version" = "$velociraptor_version" ] && [ "${TRIAGE_TARGETS_CHANGED:-false}" != "true" ] && [ "${LINUX_TRIAGE_TARGETS_CHANGED:-false}" != "true" ] && [ -n "${SKIP_IF_VERSION_UNCHANGED:-}" ]; then
  echo "Velociraptor version unchanged ($velociraptor_version) and all triage targets unchanged; skipping build."
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "VELO_VERSION_CHANGED=false" >> "$GITHUB_ENV"
  fi
  exit 0
fi

# Log what triggered the build
if [ "$stored_version" != "$velociraptor_version" ]; then
  echo "Build triggered: Velociraptor version changed ($stored_version -> $velociraptor_version)"
fi
if [ "${TRIAGE_TARGETS_CHANGED:-false}" = "true" ]; then
  echo "Build triggered: Windows.Triage.Targets artifact changed"
fi
if [ "${LINUX_TRIAGE_TARGETS_CHANGED:-false}" = "true" ]; then
  echo "Build triggered: Linux.Triage.UAC artifact changed"
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

# Compute SHA256 hash of downloaded artifact for integrity verification
ARTIFACT_SHA256=$(sha256sum Windows.Triage.Targets.zip | cut -d' ' -f1)
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

# Compute SHA256 hash of downloaded Linux artifact for integrity verification
LINUX_ARTIFACT_SHA256=$(sha256sum Linux.Triage.UAC.zip | cut -d' ' -f1)
echo "Linux.Triage.UAC.zip SHA256: $LINUX_ARTIFACT_SHA256"

# Re-fetch ETag after download to detect race conditions (artifact changed during build)
if [ -n "${LINUX_TRIAGE_ETAG:-}" ]; then
  POST_DOWNLOAD_HEADERS=$(curl -sI --fail --max-time 30 "$LINUX_ARTIFACT_URL" 2>/dev/null || true)
  POST_DOWNLOAD_ETAG=$(echo "$POST_DOWNLOAD_HEADERS" | grep -im1 "^etag:" | tr -d '\r' | sed 's/^[Ee][Tt][Aa][Gg]: *//')

  if [ -z "$POST_DOWNLOAD_ETAG" ]; then
    echo "Warning: Could not verify Linux artifact ETag after download (HEAD request returned no ETag)" >&2
    echo "Continuing with SHA256 verification as fallback..." >&2
  elif [ "$LINUX_TRIAGE_ETAG" != "$POST_DOWNLOAD_ETAG" ]; then
    echo "Error: Linux artifact ETag changed during download (race condition detected)" >&2
    echo "  Pre-download ETag:  $LINUX_TRIAGE_ETAG" >&2
    echo "  Post-download ETag: $POST_DOWNLOAD_ETAG" >&2
    echo "This indicates the artifact was updated while we were building." >&2
    echo "Please re-run the build to get the latest version." >&2
    rm -f Linux.Triage.UAC.zip
    exit 1
  else
    echo "Linux artifact ETag verified: artifact unchanged during download"
  fi
fi

# Verify Linux artifact hash against previously stored value (detect tampering if ETag reused)
if [ -f data/velociraptor-version.json ]; then
  STORED_LINUX_SHA256=$(jq -r '.linux_triage_targets_sha256 // ""' data/velociraptor-version.json 2>/dev/null || echo "")
  STORED_LINUX_ETAG=$(jq -r '.linux_triage_targets_etag // ""' data/velociraptor-version.json 2>/dev/null || echo "")
  if [ -n "$STORED_LINUX_SHA256" ] && [ -n "$STORED_LINUX_ETAG" ] && [ "$STORED_LINUX_ETAG" = "${LINUX_TRIAGE_ETAG:-}" ]; then
    if [ "$STORED_LINUX_SHA256" != "$LINUX_ARTIFACT_SHA256" ]; then
      echo "SECURITY WARNING: Linux artifact hash mismatch detected!" >&2
      echo "  ETag is unchanged: $STORED_LINUX_ETAG" >&2
      echo "  Previous SHA256:   $STORED_LINUX_SHA256" >&2
      echo "  Current SHA256:    $LINUX_ARTIFACT_SHA256" >&2
      echo "This could indicate artifact tampering or cache inconsistency." >&2
      echo "Failing build for manual investigation." >&2
      rm -f Linux.Triage.UAC.zip
      exit 1
    fi
    echo "Linux artifact hash verified: matches previously stored value"
  fi
fi

unzip -o Linux.Triage.UAC.zip -d ./datastore/artifact_definitions/Linux/Triage
rm Linux.Triage.UAC.zip

# Capture build timestamp in ISO 8601 UTC format
BUILD_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Write metadata JSON using jq for proper escaping (prevents JSON injection)
echo "Writing build metadata..."
METADATA_ARGS=(--arg ver "$velociraptor_version" --arg sha "$ARTIFACT_SHA256" --arg linux_sha "$LINUX_ARTIFACT_SHA256" --arg ts "$BUILD_TIMESTAMP")
METADATA_FIELDS='velociraptor_version: $ver, triage_targets_sha256: $sha, linux_triage_targets_sha256: $linux_sha, last_build_timestamp: $ts'

if [ -n "${TRIAGE_ETAG:-}" ]; then
  METADATA_ARGS+=(--arg etag "$TRIAGE_ETAG")
  METADATA_FIELDS="$METADATA_FIELDS, triage_targets_etag: \$etag"
fi
if [ -n "${LINUX_TRIAGE_ETAG:-}" ]; then
  METADATA_ARGS+=(--arg linux_etag "$LINUX_TRIAGE_ETAG")
  METADATA_FIELDS="$METADATA_FIELDS, linux_triage_targets_etag: \$linux_etag"
fi

jq -n "${METADATA_ARGS[@]}" "{$METADATA_FIELDS}" > data/velociraptor-version.json
echo "Metadata written to data/velociraptor-version.json"

# Validate artifact definitions (borrowed from upstream test.yml)
echo "Validating artifact definitions..."
ALL_ARTIFACT_FILES=()

WINDOWS_ARTIFACT_GLOB="./datastore/artifact_definitions/Windows/Triage/*.yaml"
if compgen -G "$WINDOWS_ARTIFACT_GLOB" > /dev/null; then
  ALL_ARTIFACT_FILES+=($WINDOWS_ARTIFACT_GLOB)
else
  echo "Error: No Windows artifact definition files found matching $WINDOWS_ARTIFACT_GLOB" >&2
  exit 1
fi

LINUX_ARTIFACT_GLOB="./datastore/artifact_definitions/Linux/Triage/*.yaml"
if compgen -G "$LINUX_ARTIFACT_GLOB" > /dev/null; then
  ALL_ARTIFACT_FILES+=($LINUX_ARTIFACT_GLOB)
else
  echo "Error: No Linux artifact definition files found matching $LINUX_ARTIFACT_GLOB" >&2
  exit 1
fi

./velociraptor artifacts verify --builtin -v "${ALL_ARTIFACT_FILES[@]}"

# Build the x64 collector
echo "Building Windows x64 collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec.yaml

# Build the x86 (32-bit) collector using the same datastore
echo "Building Windows x86 collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec_x86.yaml

# Build the Linux collector using the same datastore
echo "Building Linux collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec_linux.yaml
