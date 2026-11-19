#!/usr/bin/env bash
# Build dist/loglens_<version>_amd64.deb: a self-contained package for Debian-family
# distributions (Debian 12+, Ubuntu 22.04+, Kali, Parrot, Mint...).
#
# Distro Pythons differ (Debian 12: 3.11, Ubuntu 22.04: 3.10) and LogLens needs 3.12+,
# so the package carries its own relocatable CPython (python-build-standalone, via uv)
# and its locked dependencies under /opt/loglens. It needs only standard system
# libraries (X11/Wayland, OpenGL, fontconfig, D-Bus) from the distribution.
#
# Usage: packaging/deb/build-deb.sh            (needs uv, dpkg-deb, fakeroot)
#        STAGE_ONLY=1 packaging/deb/build-deb.sh   (just build/stage/, used by AppImage)
set -euo pipefail
cd "$(dirname "$0")/../.."

PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
ARCH="amd64"
MAINTAINER="${MAINTAINER:-LogLens maintainers <maintainers@loglens.invalid>}"
BUILD="build"
STAGE="$BUILD/stage"          # the /opt/loglens tree, shared with the AppImage build
ROOT="$BUILD/deb/root"        # the package root
APP="$STAGE/opt/loglens"

echo "==> staging LogLens $VERSION with Python $PYTHON_VERSION"
rm -rf "$STAGE" "$BUILD/deb" "$BUILD/python"
mkdir -p "$APP" "$BUILD/wheel"

# 1. A relocatable CPython.
uv python install "$PYTHON_VERSION" --install-dir "$BUILD/python" --no-bin >/dev/null
src_python="$(find "$BUILD/python" -maxdepth 1 -type d -name "cpython-$PYTHON_VERSION*-linux-x86_64-gnu" | head -1)"
cp -a "$src_python" "$APP/python"
PY="$APP/python/bin/python$PYTHON_VERSION"
rm -f "$APP"/python/lib/python*/EXTERNALLY-MANAGED

# 2. Locked runtime dependencies, then LogLens itself.
uv export --frozen --no-dev --no-hashes --no-emit-project --format requirements-txt \
    > "$BUILD/wheel/requirements.txt"
uv build --wheel --out-dir "$BUILD/wheel" >/dev/null
uv pip install --quiet --python "$PY" -r "$BUILD/wheel/requirements.txt"
uv pip install --quiet --python "$PY" --no-deps "$BUILD"/wheel/loglens-"$VERSION"-*.whl

# 3. Trim what LogLens never loads (Qt Quick/QML/WebEngine/3D/Multimedia..., Tk, tests).
site="$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
qt="$site/PySide6/Qt"
for family in WebEngine Quick Qml 3D Multimedia Pdf Designer Location Positioning Sensors \
              SerialPort SerialBus Bluetooth Nfc RemoteObjects Scxml StateMachine \
              TextToSpeech WebChannel WebSockets WebView HttpServer Graphs DataVisualization \
              VirtualKeyboard ShaderTools SpatialAudio Help Test Sql UiTools Concurrent \
              NetworkAuth Xml Charts3D Lottie Protobuf Grpc; do
    rm -rf "$qt"/lib/libQt6"$family"* "$site"/PySide6/Qt"$family"* "$site"/PySide6/lib*"$family"* 2>/dev/null || true
done
rm -rf "$qt/qml" "$qt/translations" "$qt/libexec" "$qt/resources/qtwebengine"* \
       "$site"/PySide6/{designer,assistant,linguist,lupdate,lrelease,qmlls,qmllint,qmlformat,balsam*,Assistant*,Designer*,Linguist*} \
       "$site"/PySide6/{examples,include,glue,typesystems,scripts} \
       "$site"/PySide6/Qt/plugins/{designer,qmltooling,sceneparsers,geometryloaders,renderers,assetimporters,multimedia,position,sensors,sqldrivers,webview,texttospeech,canbus,qmlls} \
       "$site"/shiboken6_generator "$site"/PySide6/*.pyi 2>/dev/null || true
rm -rf "$APP"/python/lib/python*/{test,idlelib,tkinter,turtledemo,ensurepip,lib2to3} \
       "$APP"/python/lib/{libtcl*,libtk*,tcl*,tk*,itcl*,thread*,pkgconfig} \
       "$APP"/python/include "$APP"/python/share "$site"/pip* 2>/dev/null || true
# Keep only the Qt bindings LogLens imports (plus QtSvg for icons) and the shared
# libraries they and the platform plugins actually load (ldd closure).
"$PY" -I - "$site/PySide6" <<'TRIM'
import pathlib, re, subprocess, sys
pyside = pathlib.Path(sys.argv[1])
lib = pyside / "Qt" / "lib"
keep_modules = {"QtCore", "QtGui", "QtWidgets", "QtCharts", "QtSvg", "QtDBus", "QtOpenGL",
                "QtOpenGLWidgets"}
for module in pyside.glob("Qt*.abi3.so"):
    if module.name.split(".")[0] not in keep_modules:
        module.unlink()
        for stub in pyside.glob(module.name.split(".")[0] + ".py*"):
            stub.unlink()

def deps(path):
    out = subprocess.run(["ldd", str(path)], capture_output=True, text=True).stdout
    return re.findall(r"=> (\S+) ", out), "not found" in out

plugins = pyside / "Qt" / "plugins"
# A desktop client needs xcb, wayland (client side) and offscreen; not compositor
# (server) plugins, framebuffer/EGLFS/VNC platforms or generic input drivers.
for name in ("platforms/libqeglfs.so", "platforms/libqlinuxfb.so", "platforms/libqvnc.so",
             "platforms/libqminimalegl.so", "platforms/libqvkkhrdisplay.so"):
    (plugins / name).unlink(missing_ok=True)
for folder in ("egldeviceintegrations", "wayland-graphics-integration-server",
               "wayland-hardware-layer-integration", "generic", "printsupport"):
    for item in sorted((plugins / folder).rglob("*"), reverse=True):
        item.unlink() if item.is_file() else item.rmdir()
    if (plugins / folder).exists():
        (plugins / folder).rmdir()
while True:  # drop plugins whose libraries are gone, until nothing changes
    broken = [p for p in (pyside / "Qt" / "plugins").rglob("*.so") if deps(p)[1]]
    for plugin in broken:
        plugin.unlink()
    roots = [*pyside.glob("Qt*.abi3.so"), *pyside.glob("libpyside6*.so*"),
             *(pyside / "Qt" / "plugins").rglob("*.so")]
    needed, todo = set(), list(roots)
    while todo:
        for dep in deps(todo.pop())[0]:
            dep = pathlib.Path(dep).resolve()
            if dep.parent == lib.resolve() and dep not in needed:
                needed.add(dep)
                todo.append(dep)
    removed = 0
    for so in lib.glob("*.so*"):
        if so.resolve() not in needed and so.is_file():
            so.unlink()
            removed += 1
    if not broken and not removed:
        break
TRIM
find "$APP" -name "__pycache__" -type d -prune -exec rm -rf {} +
# Byte-compile once, so nothing is written under /opt at run time and startup is fast.
"$PY" -m compileall -q -j 0 -x '/(test|lib2to3)/' "$APP/python/lib" >/dev/null || true

# 4. Launchers: isolated mode (-I) ignores PYTHONPATH, user site-packages and the cwd;
#    -B never writes bytecode (all of it was compiled above), so /opt stays as installed.
mkdir -p "$STAGE/usr/bin"
for pair in "loglens:loglens.gui.app" "loglens-cli:loglens.cli" "loglens-helper:loglens.helper.server"; do
    name="${pair%%:*}" module="${pair#*:}"
    cat > "$STAGE/usr/bin/$name" <<LAUNCHER
#!/bin/sh
exec /opt/loglens/python/bin/python$PYTHON_VERSION -I -B -c 'import sys; from $module import main; sys.exit(main())' "\$@"
LAUNCHER
    chmod 0755 "$STAGE/usr/bin/$name"
done

# 5. Desktop integration and helper files.
share="$STAGE/usr/share"
install -Dm0644 packaging/share/org.loglens.LogLens.desktop "$share/applications/org.loglens.LogLens.desktop"
install -Dm0644 packaging/share/org.loglens.LogLens.metainfo.xml "$share/metainfo/org.loglens.LogLens.metainfo.xml"
install -Dm0644 packaging/share/org.loglens.LogLens.svg "$share/icons/hicolor/scalable/apps/org.loglens.LogLens.svg"
for size in 48 64 128 256; do
    mkdir -p "$share/icons/hicolor/${size}x${size}/apps"
done
QT_QPA_PLATFORM=offscreen "$PY" -I - "$share" <<'RENDER'
import sys
from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer
app = QGuiApplication(["render"])
share = sys.argv[1]
svg = QSvgRenderer(f"{share}/icons/hicolor/scalable/apps/org.loglens.LogLens.svg")
for size in (48, 64, 128, 256):
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    painter = QPainter(image)
    svg.render(painter)
    painter.end()
    image.save(f"{share}/icons/hicolor/{size}x{size}/apps/org.loglens.LogLens.png")
RENDER
install -Dm0644 packaging/helper/loglens-helper.socket "$STAGE/usr/lib/systemd/system/loglens-helper.socket"
install -Dm0644 packaging/helper/loglens-helper.service "$STAGE/usr/lib/systemd/system/loglens-helper.service"
install -Dm0644 packaging/helper/loglens-helper.sysusers.conf "$STAGE/usr/lib/sysusers.d/loglens-helper.conf"
install -Dm0644 packaging/helper/org.loglens.helper.policy "$share/polkit-1/actions/org.loglens.helper.policy"
install -Dm0644 packaging/helper/helper.toml "$STAGE/etc/loglens/helper.toml"
doc="$share/doc/loglens"
mkdir -p "$doc"
cp README.md CHANGELOG.md "$doc/" 2>/dev/null || true
cp docs/*.md "$doc/" 2>/dev/null || true
printf 'LogLens is MIT licensed. Bundled: CPython (PSF license), Qt for Python / Qt (LGPLv3),\nand the Python packages listed in /opt/loglens/requirements.txt (their own licenses).\n' > "$doc/copyright"
cp "$BUILD/wheel/requirements.txt" "$APP/requirements.txt"

[ -n "${STAGE_ONLY:-}" ] && { echo "==> staged in $STAGE"; exit 0; }

# 6. The Debian package.
echo "==> packaging"
mkdir -p "$(dirname "$ROOT")"
mkdir -p "$(dirname "$ROOT")"
cp -a "$STAGE" "$ROOT"
mkdir -p "$ROOT/DEBIAN"
size_kb="$(du -sk --exclude=DEBIAN "$ROOT" | cut -f1)"
sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$ARCH/" -e "s/@SIZE@/$size_kb/" \
    -e "s|@MAINTAINER@|$MAINTAINER|" packaging/deb/control.in > "$ROOT/DEBIAN/control"
echo "/etc/loglens/helper.toml" > "$ROOT/DEBIAN/conffiles"
install -m0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$ROOT/DEBIAN/"
mkdir -p dist
out="dist/loglens_${VERSION}_${ARCH}.deb"
fakeroot dpkg-deb --root-owner-group -Zxz --build "$ROOT" "$out" >/dev/null
echo "==> $out ($(du -h "$out" | cut -f1), installed size $((size_kb / 1024)) MB)"
