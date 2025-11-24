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

# Update metadata used by the static site
mkdir -p data
cat <<EOF > data/velociraptor-version.json
{
  "velociraptor_version": "$velociraptor_version"
}
EOF

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

# Run the collector using the workspace configuration file
mkdir -p ./datastore/artifact_definitions/Windows/Triage
wget https://triage.velocidex.com/docs/windows.triage.targets/Windows.Triage.Targets.zip
unzip -o Windows.Triage.Targets.zip -d ./datastore/artifact_definitions/Windows/Triage
rm Windows.Triage.Targets.zip
./velociraptor collector --datastore ./datastore/ ./config/spec.yaml
