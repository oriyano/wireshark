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
    signal captureRequested()

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
                text: qsTr("Drop a .pcap or .pcapng file here, choose one, or capture live traffic. Kitsune reads every packet and shows you who is talking, what they say, and why it matters.")
                color: Theme.textMuted
                font.pixelSize: Theme.fontLarge
            }
            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 6
                spacing: 12
                Button {
                    id: openButton
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
                Button {
                    id: captureButton
                    text: qsTr("Capture live…")
                    onClicked: root.captureRequested()
                    contentItem: Text {
                        text: captureButton.text
                        color: Theme.text
                        font.pixelSize: Theme.fontLarge
                        font.weight: Font.DemiBold
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                    }
                    background: Rectangle {
                        implicitWidth: 170
                        implicitHeight: 42
                        radius: Theme.radiusSmall + 2
                        color: captureButton.hovered ? Theme.surfaceHover : Theme.surfaceRaised
                        border.color: Theme.borderStrong
                    }
                }
            }
        }
    }
}
