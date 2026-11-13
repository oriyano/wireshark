# Kitsune

Kitsune is a QML interface on top of the Wireshark engine, designed for
training and education. It links the same libraries as Wireshark
(`epan` for dissection, `wiretap` for capture files) and replaces only
the user interface.

This is step 1 of the plan: a working application that opens a capture,
shows a fast packet list, and ships dark, light and system-color themes.

## Building

Kitsune is off by default. Turn it on with `-DBUILD_kitsune=ON`:

```sh
cmake -G Ninja -DBUILD_kitsune=ON ..
ninja kitsune
./run/kitsune capture.pcapng
```

It needs Qt 6 with the Quick, QuickControls2, Qml and Shapes modules.
Qt 6.5 or later is recommended; Qt 6.4 works, but builds without
ahead-of-time QML compilation because of a qmlcachegen bug in that
release.

### Windows

Follow the Wireshark Developer's Guide for Windows (Visual Studio 2022
with the C++ workload, and the Qt Online Installer with
"MSVC 2022 64-bit", "Qt 5 Compatibility Module" and "Qt Multimedia"),
then configure with `-DBUILD_kitsune=ON` added to the usual CMake
command line. Visual Studio 2026 (MSVC 14.5x) also works with Qt's
msvc2022_64 kit; it raises a new warning in upstream `wiretap/blf.c`, so
add `-DENABLE_WERROR=OFF` until that is fixed upstream. After building,
run `windeployqt --qmldir <source>/kitsune/qml run/kitsune.exe`.

## Command-line options

| Option                 | What it does                                                  |
|------------------------|---------------------------------------------------------------|
| `--theme <mode>`       | `system`, `light` or `dark` for this run                      |
| `--bench <file>`       | Load the file, read every packet list row, print timings      |
| `--screenshot <png>`   | Save a picture of the window once the file loads, then exit   |

## Test data

`tools/make_synthetic_capture.py` writes a synthetic office-network
capture of any size. It is generated, not captured, so it contains no
private data:

```sh
python3 tools/make_synthetic_capture.py office-1m.pcap 1000000
./run/kitsune --bench office-1m.pcap
```

## Layout

| Path                         | Contents                                              |
|------------------------------|-------------------------------------------------------|
| `engine/captureengine.*`     | libwireshark session; first pass on a worker thread   |
| `engine/kitsunesettings.*`   | Persistent UI settings (theme)                        |
| `models/packetlistmodel.*`   | Packet list model; dissects only rows a view asks for |
| `qml/Theme.qml`              | Color, type and spacing tokens for all three themes   |
| `qml/*.qml`                  | Window, navigation, packet list and placeholder views |
