#!/usr/bin/env bash
# Build dist/LogLens-<version>-x86_64.AppImage from the same staged tree as the .deb.
# The AppImage runs LogLens from any folder; it does not include loglens-helper (a
# system service) - install the .deb for that.
# Needs network once to fetch appimagetool (or set APPIMAGETOOL=/path/to/appimagetool).
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
STAGE_ONLY=1 packaging/deb/build-deb.sh
APPDIR="build/LogLens.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/share"
cp -a build/stage/opt "$APPDIR/opt"
cp -a build/stage/usr/share/icons build/stage/usr/share/metainfo "$APPDIR/usr/share/"
cp packaging/share/org.loglens.LogLens.desktop "$APPDIR/"
cp packaging/share/org.loglens.LogLens.svg "$APPDIR/org.loglens.LogLens.svg"
cp packaging/share/org.loglens.LogLens.svg "$APPDIR/.DirIcon"
cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
# Relocatable: the bundled interpreter lives next to this script.
HERE="$(dirname "$(readlink -f "$0")")"
case "$(basename "${ARGV0:-loglens}")" in
    loglens-cli*) module=loglens.cli ;;
    *) module=loglens.gui.app ;;
esac
exec "$HERE/opt/loglens/python/bin/python3.12" -I -c "import sys; from $module import main; sys.exit(main())" "$@"
APPRUN
chmod 0755 "$APPDIR/AppRun"
tool="${APPIMAGETOOL:-build/appimagetool-x86_64.AppImage}"
if [ ! -x "$tool" ]; then
    curl -fsSL -o "$tool" \
        https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
    chmod +x "$tool"
fi
mkdir -p dist
ARCH=x86_64 "$tool" --appimage-extract-and-run --no-appstream "$APPDIR" \
    "dist/LogLens-$VERSION-x86_64.AppImage" >/dev/null
echo "==> dist/LogLens-$VERSION-x86_64.AppImage ($(du -h "dist/LogLens-$VERSION-x86_64.AppImage" | cut -f1))"
