#!/bin/bash

set -e

PLUGIN_SLUG="attacklog"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$(mktemp -d)"
OUTPUT_DIR="${SCRIPT_DIR}/dist"
OUTPUT_ZIP="${OUTPUT_DIR}/${PLUGIN_SLUG}.zip"

cleanup() {
	rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUTPUT_ZIP}"

PLUGIN_BUILD_DIR="${BUILD_DIR}/${PLUGIN_SLUG}"
mkdir -p "${PLUGIN_BUILD_DIR}"

rsync -a \
	--exclude ".git" \
	--exclude ".gitignore" \
	--exclude ".github" \
	--exclude ".idea" \
	--exclude "dist" \
	--exclude "node_modules" \
	--exclude "pack.sh" \
	--exclude "*.zip" \
	--exclude ".DS_Store" \
	"${SCRIPT_DIR}/" "${PLUGIN_BUILD_DIR}/"

cd "${BUILD_DIR}"
zip -r -q "${OUTPUT_ZIP}" "${PLUGIN_SLUG}"

echo "Plugin packaged successfully: ${OUTPUT_ZIP}"