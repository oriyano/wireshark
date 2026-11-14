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

| Option                    | What it does                                                    |
|---------------------------|-----------------------------------------------------------------|
| `--theme <mode>`          | `system`, `light` or `dark` for this run (not saved)            |
| `--bench <file>`          | Load the file, read every packet list row, print timings        |
| `--filter <expr>`         | With `--bench`, also time a display filter                      |
| `--inventory <file>`      | Print the hosts, services and OS guesses found in the file      |
| `--view <view>`           | Start on `packets`, `details`, `bytes` or `map`                 |
| `--display-filter <expr>` | Apply a display filter once the file loads                      |
| `--filter-draft <expr>`   | Type a filter into the filter bar without applying it           |
| `--select <n>`            | Select packet `n` once the file loads                           |
| `--details-row <row>`     | Select a row of the packet details tree                         |
| `--subnet <cidr>`, `--host <row>` | Open a subnet, and a host in it, in the network view    |
| `--large-file-mode on\|off` | Override the saved large-file mode setting for this run       |
| `--screenshot <png>`      | Save a picture of the window once the file loads, then exit     |
| `--screenshot-delay <ms>` | Take the screenshot after `ms` instead                          |
| `--capture <interface>`   | Start a live capture (`--display-filter` then applies after 1.5 s) |
| `--capture-seconds <n>`   | With `--capture`, stop after `n` seconds                        |
| `--ring-buffer <files>:<MB>` | Capture to a ring buffer of that many files of that size     |

## Tests

`kitsune_tests` covers the host inventory (which packets need a full
protocol tree, the raw TCP handshake parser, and the OS reasoning) and
the conversation with dumpcap (its messages, interface list and
command line).

```sh
ninja kitsune_tests && ./run/kitsune_tests     # or: ctest -R kitsune
```

## Test data

`tools/make_synthetic_capture.py` writes a synthetic office-network
capture of any size. It is generated, not captured, so it contains no
private data:

```sh
python3 tools/make_synthetic_capture.py office-1m.pcap 1000000
./run/kitsune --bench office-1m.pcap --filter http
./run/kitsune --inventory office-1m.pcap
```

## How the engine is arranged

All libwireshark calls happen on one engine thread (`EngineWorker`).
The interface talks to it through `CaptureEngine`, which turns results
into properties and signals; every request carries a generation number
so that answers to an older file, filter or selection are dropped.

The first pass also builds the host inventory. Building a protocol
tree roughly doubles the cost of dissecting a packet, so a quick look
at the raw headers (`HostInventory::peek`) decides which packets get
one: those that can carry a name, banner or OS hint (ARP, DHCP, DNS
responses, NetBIOS, SMB, and payloads that start like HTTP or SSH).
TCP handshake options are read straight from the bytes. Everything
else only adds to traffic counts, which come from the engine without
a tree.

### Large-file mode

TCP sequence analysis (retransmissions, lost segments, bytes in flight)
holds most of the engine's memory on a large capture. Large-file mode,
a switch in the file bar, turns it off: on 1M synthetic packets peak
memory drops from 1,510 MiB to 1,067 MiB. The analysis flags are not
available while it's on, so it is off by default. Changing it reloads
the open file.

## Live capture

Kitsune never captures packets itself. The capture view runs dumpcap,
the capture helper installed next to it, which is the only part that
needs capture rights (Npcap on Windows; the `wireshark` group or
capabilities on Linux; ChmodBPF on macOS). dumpcap runs with
`-Z none` and reports on stderr in its sync pipe format: the file it is
writing, how many packets it added, drops and errors. `CaptureSession`
passes those on, and the engine reads the new packets from the growing
file, updates the packet list, a display filter that is applied, and the
host inventory (at most once a second).

Stopping sends SIGTERM on Linux and macOS; on Windows dumpcap watches a
named pipe (`--signal-pipe`) that Kitsune writes to. Either way dumpcap
finishes the file before it exits.

With a ring buffer, dumpcap writes a set of files of a fixed size and
deletes the oldest. Kitsune follows it to each new file, so the packet
list always shows the file being written.

```sh
./run/kitsune --capture lo --capture-seconds 10
./run/kitsune --capture eth0 --ring-buffer 5:100 --display-filter dns
```

## Layout

| Path                         | Contents                                                  |
|------------------------------|-----------------------------------------------------------|
| `capture/capturesession.*`   | Live capture: runs dumpcap and passes on what it reports  |
| `capture/syncpipe.*`         | dumpcap's command line, messages and interface list       |
| `engine/captureengine.*`     | GUI-side handle on the engine: properties and signals     |
| `engine/engineworker.*`      | Engine thread: first pass, rows, details, filters         |
| `engine/hostinventory.*`     | Passive host, service and OS discovery                    |
| `engine/kitsunesettings.*`   | Persistent UI settings (theme, subnet names)              |
| `models/packetlistmodel.*`   | Packet list model; dissects only rows a view asks for     |
| `models/packetdetailsmodel.*`| Selected packet's layers (tree) and bytes (hex rows)      |
| `models/hostmodels.*`        | Subnet and host list models for the network view          |
| `qml/Theme.qml`              | Color, type and spacing tokens for all three themes       |
| `qml/PacketsPage.qml`        | Filter bar, packet list, details and bytes                |
| `qml/NetworkView.qml`        | Topology map, subnets, hosts, and the host panel          |
| `qml/CaptureView.qml`        | Interfaces, capture filter, ring buffer, start and stop   |
| `qml/*.qml`                  | Window, navigation and the other views                    |
| `tests/`                     | Unit tests                                                |
