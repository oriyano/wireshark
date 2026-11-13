// CaptureStatusPanel.qml
//
// Kitsune - capture state and packet counts.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
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
            Rectangle { width: 9; height: 9; radius: 5; color: captureEngine.loading ? Theme.warning : Theme.success }
            Text {
                text: captureEngine.loading ? qsTr("Reading file") : captureEngine.hasFile ? qsTr("File loaded") : qsTr("Idle")
                color: Theme.textMuted
                font.pixelSize: Theme.fontSmall + 1
            }
        }
        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.border }
        CountRow { label: qsTr("Packets"); value: captureEngine.formatCount(captureEngine.packetCount) }
        CountRow { label: qsTr("Displayed"); value: captureEngine.formatCount(captureEngine.loading ? 0 : captureEngine.displayedCount) }
        CountRow { label: qsTr("Dropped"); value: "—" }
    }
}
