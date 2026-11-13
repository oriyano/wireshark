// WelcomeView.qml
//
// Kitsune - shown when no capture is open. Open by button or drop.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root
    signal openRequested()

    DropArea {
        id: drop
        anchors.fill: parent
        onDropped: (event) => {
            if (event.hasUrls && event.urls.length > 0)
                captureEngine.openFile(event.urls[0])
        }
    }

    Rectangle {
        anchors.centerIn: parent
        width: Math.min(560, parent.width - 64)
        height: 320
        radius: Theme.radius + 6
        color: drop.containsDrag ? Theme.accentSoft : "transparent"
        border.width: 2
        border.color: drop.containsDrag ? Theme.accent : Theme.border

        ColumnLayout {
            anchors.centerIn: parent
            spacing: 14

            Icon {
                Layout.alignment: Qt.AlignHCenter
                name: "map"
                size: 56
                strokeWidth: 1.4
                color: Theme.accent
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                text: qsTr("Open a capture to start exploring")
                color: Theme.text
                font.pixelSize: 22
                font.weight: Font.DemiBold
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                Layout.maximumWidth: 440
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                text: qsTr("Drop a .pcap or .pcapng file here, or choose one. Kitsune reads every packet and shows you who is talking, what they say, and why it matters.")
                color: Theme.textMuted
                font.pixelSize: Theme.fontLarge
            }
            Button {
                id: openButton
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 6
                text: qsTr("Open capture file…")
                onClicked: root.openRequested()
                contentItem: Text {
                    text: openButton.text
                    color: Theme.onAccent
                    font.pixelSize: Theme.fontLarge
                    font.weight: Font.DemiBold
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                }
                background: Rectangle {
                    implicitWidth: 200
                    implicitHeight: 42
                    radius: Theme.radiusSmall + 2
                    color: openButton.down ? Theme.accentStrong : Theme.accent
                }
            }
        }
    }
}
