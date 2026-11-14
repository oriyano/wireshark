// CaptureStatusPanel.qml
//
// Kitsune - capture state and packet counts.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    implicitHeight: column.implicitHeight + 24
    radius: Theme.radius
    color: Theme.window
    border.color: Theme.border

    component CountRow: RowLayout {
        property string label
        property string value
        Layout.fillWidth: true
        Text { text: parent.label; color: Theme.textMuted; font.pixelSize: Theme.fontSmall + 1 }
        Item { Layout.fillWidth: true }
        Text { text: parent.value; color: Theme.text; font.pixelSize: Theme.fontSmall + 1; font.family: Theme.monoFamily }
    }

    ColumnLayout {
        id: column
        anchors.fill: parent
        anchors.margins: 12
        spacing: 8

        RowLayout {
            spacing: 8
            Rectangle { width: 9; height: 9; radius: 5; color: Theme.success }
            Text { text: qsTr("Capture Status"); color: Theme.text; font.pixelSize: Theme.fontBody; font.weight: Font.DemiBold }
        }
        RowLayout {
            spacing: 8
            Rectangle {
                width: 9; height: 9; radius: 5
                color: captureSession.running ? Theme.danger : captureEngine.loading ? Theme.warning : Theme.success
                SequentialAnimation on opacity {
                    running: captureSession.running
                    loops: Animation.Infinite
                    onRunningChanged: if (!running) parent.opacity = 1
                    NumberAnimation { to: 0.25; duration: 700 }
                    NumberAnimation { to: 1; duration: 700 }
                }
            }
            Text {
                Layout.fillWidth: true
                elide: Text.ElideRight
                text: captureSession.stopping ? qsTr("Stopping capture")
                    : captureSession.running ? qsTr("Capturing on %1").arg(captureSession.interfaceName)
                    : captureEngine.loading ? qsTr("Reading file") : captureEngine.hasFile ? qsTr("File loaded") : qsTr("Idle")
                color: Theme.textMuted
                font.pixelSize: Theme.fontSmall + 1
            }
        }
        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }
        CountRow { label: qsTr("Packets"); value: captureEngine.formatCount(captureEngine.packetCount) }
        CountRow { label: qsTr("Displayed"); value: captureEngine.formatCount(captureEngine.loading ? 0 : captureEngine.displayedCount) }
        CountRow {
            label: qsTr("Dropped")
            value: captureSession.running || captureSession.filesWritten > 0 ? captureEngine.formatCount(captureSession.drops) : "—"
        }
        Button {
            id: stopButton
            visible: captureSession.running
            enabled: !captureSession.stopping
            Layout.fillWidth: true
            Layout.topMargin: 4
            implicitHeight: 32
            onClicked: captureSession.stop()
            background: Rectangle {
                radius: Theme.radiusSmall
                color: stopButton.hovered ? Qt.rgba(Theme.danger.r, Theme.danger.g, Theme.danger.b, 0.22)
                                          : Qt.rgba(Theme.danger.r, Theme.danger.g, Theme.danger.b, 0.12)
                border.color: Theme.danger
            }
            contentItem: RowLayout {
                spacing: 6
                Item { Layout.fillWidth: true }
                Icon { name: "stop"; size: 12; color: Theme.danger }
                Text {
                    text: captureSession.stopping ? qsTr("Stopping…") : qsTr("Stop capture")
                    color: Theme.danger
                    font.pixelSize: Theme.fontBody
                    font.weight: Font.DemiBold
                }
                Item { Layout.fillWidth: true }
            }
        }
    }
}
