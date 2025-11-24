#!/bin/bash
set -euo pipefail

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

# Use jq to extract the browser_download_url for the MacOS binary
download_url=$(echo "$response" | jq -r '[.assets[] | select(.name | test("velociraptor-.*-darwin-amd64$")) | .browser_download_url] | sort | reverse | .[0]')

# Check if we found a URL
if [ -z "$download_url" ] || [ "$download_url" == "null" ]; then
  echo "Error: Could not find a macOS binary in the latest release" >&2
  echo "Debug - Available assets:" >&2
  echo "$response" | jq -r '.assets[].name' >&2
  exit 1
fi

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

# Use curl instead of wget (macOS compatible)
curl -L https://triage.velocidex.com/docs/windows.triage.targets/Windows.Triage.Targets.zip -o Windows.Triage.Targets.zip
unzip -o Windows.Triage.Targets.zip -d ./datastore/artifact_definitions/Windows/Triage
rm Windows.Triage.Targets.zip

# Run the collector command
./velociraptor collector --datastore ./datastore/ ./config/spec.yaml
