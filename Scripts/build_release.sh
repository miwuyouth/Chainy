#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${1:-$ROOT_DIR/dist}"
TAG="$(git -C "$ROOT_DIR" describe --tags --exact-match HEAD 2>/dev/null || true)"

if [[ ! "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "error: HEAD must have a version tag such as v0.2.0" >&2
  exit 1
fi

if [[ -n "$(git -C "$ROOT_DIR" status --porcelain)" ]]; then
  echo "error: release builds require a clean working tree" >&2
  exit 1
fi

for command in xcodegen xcodebuild codesign hdiutil lipo shasum; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "error: required command not found: $command" >&2
    exit 1
  fi
done

VERSION="${TAG#v}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chainy-release.XXXXXX")"
DERIVED_DATA="$WORK_DIR/DerivedData"
STAGING_DIR="$WORK_DIR/dmg"
APP_PATH="$DERIVED_DATA/Build/Products/Release/Chainy.app"
DMG_PATH="$OUTPUT_DIR/Chainy-$VERSION.dmg"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$OUTPUT_DIR" "$STAGING_DIR"

cd "$ROOT_DIR"
xcodegen generate
xcodebuild \
  -project Chainy.xcodeproj \
  -scheme Chainy \
  -configuration Release \
  -destination 'generic/platform=macOS' \
  -derivedDataPath "$DERIVED_DATA" \
  ARCHS='arm64 x86_64' \
  ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO \
  build

if [[ ! -d "$APP_PATH" ]]; then
  echo "error: expected app was not produced at $APP_PATH" >&2
  exit 1
fi

BINARY_PATH="$APP_PATH/Contents/MacOS/Chainy"
ARCHITECTURES="$(lipo -archs "$BINARY_PATH")"
if [[ "$ARCHITECTURES" != *arm64* || "$ARCHITECTURES" != *x86_64* ]]; then
  echo "error: expected a universal binary, found: $ARCHITECTURES" >&2
  exit 1
fi

codesign --force --deep --sign - "$APP_PATH"
codesign --verify --deep --strict "$APP_PATH"

ditto "$APP_PATH" "$STAGING_DIR/Chainy.app"
ln -s /Applications "$STAGING_DIR/Applications"

rm -f "$DMG_PATH" "$DMG_PATH.sha256"
hdiutil create \
  -volname Chainy \
  -srcfolder "$STAGING_DIR" \
  -ov \
  -format UDZO \
  "$DMG_PATH"

(
  cd "$OUTPUT_DIR"
  shasum -a 256 "$(basename "$DMG_PATH")" > "$(basename "$DMG_PATH").sha256"
)

echo "Created $DMG_PATH"
echo "Architectures: $ARCHITECTURES"
cat "$DMG_PATH.sha256"
