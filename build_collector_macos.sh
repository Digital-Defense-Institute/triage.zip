#!/bin/bash
set -euo pipefail

# Use the native host architecture; both embedded macOS binaries must match
# its exact release version, independently of the GitHub release tag.
case "$(uname -m)" in
  arm64) host_arch=darwin-arm64 ;;
  x86_64) host_arch=darwin-amd64 ;;
  *) echo "Error: unsupported macOS host architecture" >&2; exit 1 ;;
esac

# Check prerequisites
command -v jq >/dev/null 2>&1 || { echo "Error: jq is required but not installed" >&2; exit 1; }

echo "Starting build_collector.sh (macOS version)..."

# Shared helpers: fetch/download retries, version-aware asset selection, and the
# stub verification run after every collector build.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/collector_common.sh
. "$SCRIPT_DIR/lib/collector_common.sh"

# Fetch the latest Velociraptor release information from GitHub API
response=$(fetch_with_retry "https://api.github.com/repos/Velocidex/velociraptor/releases/latest") || exit 1

# Check if response is empty
if [ -z "$response" ]; then
  echo "Error: Empty response from GitHub API" >&2
  exit 1
fi

# Identify the native host binary (highest numeric version).
asset_info=$(select_velociraptor_asset "$response" "$host_arch")
download_url=$(echo "$asset_info" | jq -r '.url')

if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
  echo "Error: Could not find a macOS binary in the latest release" >&2
  echo "Debug - Available assets:" >&2
  echo "$response" | jq -r '.assets[].name' >&2
  exit 1
fi

velociraptor_version=$(echo "$asset_info" | jq -r '.version')

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
  exit 0
fi

# Create data directory for metadata (JSON written after artifact download)
mkdir -p data

echo "Downloading Velociraptor binary from: $download_url"

# Download Velociraptor binary and make it executable (native host binary)
download_velociraptor_asset "$asset_info" "./velociraptor" || exit 1

# Pin both embedded darwin binaries to the exact host version. Resolve all
# assets before downloading so missing per-architecture releases fail clearly.
darwin_amd64_asset=$(select_velociraptor_asset "$response" "darwin-amd64" "$velociraptor_version")
darwin_arm64_asset=$(select_velociraptor_asset "$response" "darwin-arm64" "$velociraptor_version")
if [ "$(echo "$darwin_amd64_asset" | jq -r '.url // empty')" = "" ] || \
   [ "$(echo "$darwin_arm64_asset" | jq -r '.url // empty')" = "" ]; then
  echo "Error: both darwin binaries must match host v${velociraptor_version} (per-arch version skew?)." >&2
  exit 1
fi
echo "Downloading Velociraptor darwin binaries..."
download_velociraptor_asset "$darwin_amd64_asset" "./velociraptor_darwin_amd64" || exit 1
download_velociraptor_asset "$darwin_arm64_asset" "./velociraptor_darwin_arm64" || exit 1

# Download and extract Windows.Triage.Targets artifact
mkdir -p ./datastore/artifact_definitions/Windows/Triage
ARTIFACT_URL="https://triage.velocidex.com/artifacts/Windows.Triage.Targets.zip"
echo "Downloading Windows.Triage.Targets artifact..."
download_with_retry "$ARTIFACT_URL" "Windows.Triage.Targets.zip" || exit 1

# Compute SHA256 hash of downloaded artifact for integrity verification (macOS uses shasum)
ARTIFACT_SHA256=$(shasum -a 256 Windows.Triage.Targets.zip | cut -d' ' -f1)
echo "Windows.Triage.Targets.zip SHA256: $ARTIFACT_SHA256"

# Detect a mid-build republish (release raced our build); curl already ensured
# the download itself is complete.
if [ -n "${TRIAGE_ETAG:-}" ]; then
  verify_download_not_raced "$ARTIFACT_URL" "Windows.Triage.Targets.zip" "$TRIAGE_ETAG" "Windows.Triage.Targets"
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

echo "Validating artifact definitions..."
verify_triage_artifacts ./velociraptor

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
verify_collector_not_stub ./datastore/Velociraptor_Triage_Collector.exe

# Build the Linux collector using the same datastore
echo "Building Linux collector..."
./velociraptor collector --datastore ./datastore/ ./config/spec_linux.yaml
verify_collector_not_stub ./datastore/Velociraptor_Triage_Collector_Linux

# Embed the darwin velociraptor binary into each macOS collector. Both specs map
# to the single "VelociraptorCollector" tool, so register the matching arch's
# binary into the datastore inventory immediately before each build. "tools
# upload" works through a server config rather than --datastore, so generate a
# minimal config pointed at the same ./datastore the collector builds use.
# (./velociraptor is the native host binary downloaded above.)
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
adhoc_sign_macos ./datastore/Velociraptor_Triage_Collector_macOS_ARM || exit 1
verify_collector_not_stub ./datastore/Velociraptor_Triage_Collector_macOS_ARM

# Build the macOS x64 collector (re-point VelociraptorCollector to darwin-amd64)
echo "Registering darwin-amd64 binary and building macOS x64 collector..."
./velociraptor --config server.config.yaml tools upload --name VelociraptorCollector --download ./velociraptor_darwin_amd64
./velociraptor collector --datastore ./datastore/ ./config/spec_macos.yaml
adhoc_sign_macos ./datastore/Velociraptor_Triage_Collector_macOS || exit 1
verify_collector_not_stub ./datastore/Velociraptor_Triage_Collector_macOS
