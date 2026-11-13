// Icon.qml
//
// Kitsune - line icons drawn as vector paths on a 24x24 grid, so they
// take any theme color and stay sharp at any scale.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Shapes

Item {
    id: root

    property string name
    property color color: Theme.text
    property real size: 20
    property real strokeWidth: 1.8

    implicitWidth: size
    implicitHeight: size

    readonly property var paths: ({
        "capture":   "M4.9 19.1a10 10 0 0 1 0-14.2 M19.1 4.9a10 10 0 0 1 0 14.2 M7.8 16.2a6 6 0 0 1 0-8.4 M16.2 7.8a6 6 0 0 1 0 8.4 M10 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0",
        "analyze":   "M4 11a7 7 0 1 0 14 0a7 7 0 1 0-14 0 M21 21l-5-5",
        "map":       "M9.5 5a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0 M2.5 18a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0 M16.5 18a2.5 2.5 0 1 0 5 0a2.5 2.5 0 1 0-5 0 M10.8 7.2 6.2 15.8 M13.2 7.2l4.6 8.6 M7.5 18h9",
        "stats":     "M4 20V11 M10 20V5 M16 20v-7 M21 20H3",
        "convo":     "M3 5h12v8H8l-5 4z M18 9h3v11l-4-3h-6v-2",
        "expert":    "M12 3l8 3v6c0 5-3.5 8-8 9c-4.5-1-8-4-8-9V6z M12 8v5 M12 16.5v.5",
        "list":      "M9 6h12 M9 12h12 M9 18h12 M4 6h.5 M4 12h.5 M4 18h.5",
        "details":   "M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z M14 3v6h6 M8 13h8 M8 17h5",
        "bytes":     "M4 4h16v16H4z M4 9.3h16 M4 14.7h16 M9.3 4v16 M14.7 4v16",
        "graph":     "M3 3v18h18 M7 15l4-5 3 3 6-7",
        "search":    "M4 11a7 7 0 1 0 14 0a7 7 0 1 0-14 0 M21 21l-5-5",
        "bell":      "M6 16V11a6 6 0 0 1 12 0v5l2 2H4z M10 21h4",
        "help":      "M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0 M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.6v.6 M12 17v.5",
        "folder":    "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z",
        "sun":       "M8 12a4 4 0 1 0 8 0a4 4 0 1 0-8 0 M12 2v2 M12 20v2 M4.9 4.9l1.4 1.4 M17.7 17.7l1.4 1.4 M2 12h2 M20 12h2 M4.9 19.1l1.4-1.4 M17.7 6.3l1.4-1.4",
        "moon":      "M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5z",
        "monitor":   "M3 4h18v12H3z M8 20h8 M12 16v4",
        "close":     "M6 6l12 12 M18 6L6 18",
        "packets":   "M3 7l9-4 9 4-9 4z M3 12l9 4 9-4 M3 17l9 4 9-4",
        "clock":     "M3 12a9 9 0 1 0 18 0a9 9 0 1 0-18 0 M12 7v5l3 2",
        "file":      "M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z M14 3v6h6",
        "learn":     "M2 9l10-5 10 5-10 5z M6 11v5c3 2.5 9 2.5 12 0v-5 M22 9v6"
    })

    Shape {
        anchors.centerIn: parent
        width: root.size
        height: root.size
        // Multisampled layer for smooth edges on every Qt 6 version.
        layer.enabled: true
        layer.samples: 4
        layer.smooth: true

        ShapePath {
            scale: Qt.size(root.size / 24, root.size / 24)
            strokeColor: root.color
            strokeWidth: root.strokeWidth
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: root.paths[root.name] || "" }
        }
    }
}
