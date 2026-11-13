// SideBar.qml
//
// Kitsune - view list and capture status.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string currentView
    signal viewRequested(string view)

    radius: Theme.radius
    color: Theme.surface
    border.color: Theme.border

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 10
        spacing: 4

        Repeater {
            model: [
                { view: "packets", label: qsTr("Packet List"),    icon: "list" },
                { view: "details", label: qsTr("Packet Details"), icon: "details" },
                { view: "bytes",   label: qsTr("Packet Bytes"),   icon: "bytes" },
                { view: "map",     label: qsTr("Network Map"),    icon: "map" },
                { view: "graphs",  label: qsTr("I/O Graphs"),     icon: "graph" },
                { view: "stats",   label: qsTr("Statistics"),     icon: "stats" },
                { view: "learn",   label: qsTr("Learn"),          icon: "learn" }
            ]
            delegate: NavButton {
                required property var modelData
                Layout.fillWidth: true
                implicitHeight: 46
                wide: true
                text: modelData.label
                iconName: modelData.icon
                checked: root.currentView === modelData.view
                onClicked: root.viewRequested(modelData.view)
            }
        }

        Item { Layout.fillHeight: true }

        CaptureStatusPanel { Layout.fillWidth: true }
    }
}
