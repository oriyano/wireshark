// FileInfoBar.qml
//
// Kitsune - the open file and its headline numbers.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    signal openRequested()

    implicitHeight: 48
    radius: Theme.radius
    color: Theme.surface
    border.color: Theme.border

    component Stat: RowLayout {
        property string icon
        property string label
        property string value
        spacing: 8
        Icon { name: parent.icon; size: 16; color: Theme.textMuted }
        Text {
            text: parent.label.length > 0 ? parent.label + ": " + parent.value : parent.value
            color: Theme.text
            font.pixelSize: Theme.fontBody
        }
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 18
        anchors.rightMargin: 18
        spacing: 40

        RowLayout {
            spacing: 10
            Rectangle {
                width: 10; height: 10; radius: 5
                color: captureEngine.loading ? Theme.warning
                     : captureEngine.hasFile ? Theme.success : Theme.textFaint
            }
            Text {
                text: captureEngine.hasFile ? captureEngine.fileName : qsTr("No capture open")
                color: Theme.text
                font.pixelSize: Theme.fontBody
                font.weight: Font.DemiBold
            }
        }

        Stat {
            visible: captureEngine.hasFile
            icon: "packets"
            label: qsTr("Packets")
            value: captureEngine.formatCount(captureEngine.packetCount)
        }
        Stat {
            visible: captureEngine.hasFile && !captureEngine.loading
            icon: "clock"
            label: qsTr("Duration")
            value: captureEngine.duration
        }
        Stat {
            visible: captureEngine.hasFile && !captureEngine.loading
            icon: "file"
            label: qsTr("Format")
            value: captureEngine.fileTypeName
        }

        // Loading progress, replaced by the load time once done.
        RowLayout {
            visible: captureEngine.loading
            spacing: 10
            ProgressBar {
                id: progress
                Layout.preferredWidth: 180
                value: captureEngine.loadProgress
                background: Rectangle { implicitHeight: 6; radius: 3; color: Theme.border }
                contentItem: Item {
                    Rectangle {
                        width: progress.visualPosition * parent.width
                        height: parent.height
                        radius: 3
                        color: Theme.accent
                    }
                }
            }
            Text {
                text: qsTr("Loading %1%").arg(Math.round(captureEngine.loadProgress * 100))
                color: Theme.textMuted
                font.pixelSize: Theme.fontSmall
            }
        }
        Text {
            visible: captureEngine.hasFile && !captureEngine.loading
            text: qsTr("Loaded in %1 s").arg((captureEngine.loadTimeMs / 1000).toFixed(2))
            color: Theme.textFaint
            font.pixelSize: Theme.fontSmall
        }

        Item { Layout.fillWidth: true }
    }
}
