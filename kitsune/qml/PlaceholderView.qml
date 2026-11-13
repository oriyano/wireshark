// PlaceholderView.qml
//
// Kitsune - stands in for views that later steps of the plan build.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Layouts

Item {
    id: root
    property string view

    readonly property var info: ({
        "map":     { icon: "map",     title: qsTr("Network Map"),    body: qsTr("Hosts, subnets, services and operating systems discovered from the capture, on a clickable map.") },
        "details": { icon: "details", title: qsTr("Packet Details"), body: qsTr("The selected packet, decoded layer by layer, with plain-language explanations.") },
        "bytes":   { icon: "bytes",   title: qsTr("Packet Bytes"),   body: qsTr("The raw bytes of the selected packet, linked to the fields they belong to.") },
        "graphs":  { icon: "graph",   title: qsTr("I/O Graphs"),     body: qsTr("Traffic over time.") },
        "stats":   { icon: "stats",   title: qsTr("Statistics"),     body: qsTr("Protocol hierarchy, endpoints and conversations.") },
        "convo":   { icon: "convo",   title: qsTr("Conversations"),  body: qsTr("Who talked to whom, how much and for how long.") },
        "expert":  { icon: "expert",  title: qsTr("Expert Info"),    body: qsTr("Warnings and errors the dissectors found, grouped by severity.") },
        "capture": { icon: "capture", title: qsTr("Capture"),        body: qsTr("Live capture from your network interfaces.") },
        "learn":   { icon: "learn",   title: qsTr("Learn"),          body: qsTr("Guided labs and field-by-field explanations.") }
    })
    readonly property var current: info[view] || { icon: "help", title: view, body: "" }

    ColumnLayout {
        anchors.centerIn: parent
        spacing: 12
        Icon { Layout.alignment: Qt.AlignHCenter; name: root.current.icon; size: 48; strokeWidth: 1.4; color: Theme.accent }
        Text {
            Layout.alignment: Qt.AlignHCenter
            text: root.current.title
            color: Theme.text
            font.pixelSize: 22
            font.weight: Font.DemiBold
        }
        Text {
            Layout.alignment: Qt.AlignHCenter
            Layout.maximumWidth: 460
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
            text: root.current.body
            color: Theme.textMuted
            font.pixelSize: Theme.fontLarge
        }
        Text {
            Layout.alignment: Qt.AlignHCenter
            text: qsTr("Coming in a later step")
            color: Theme.textFaint
            font.pixelSize: Theme.fontSmall
        }
    }
}
