// PacketListView.qml
//
// Kitsune - the packet list. TableView only creates delegates for the
// rows on screen, and the model only dissects those rows, so scrolling
// cost does not grow with the size of the capture.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    // The selected packet lives in the engine, so every view agrees.
    readonly property int selectedRow: captureEngine.selectedFrame > 0 && modelRevision >= 0
                                        ? packetListModel.rowOfFrame(captureEngine.selectedFrame) : -1
    property int modelRevision: 0
    Connections {
        target: packetListModel
        function onModelReset() {
            root.modelRevision++
            if (root.selectedRow >= 0)
                Qt.callLater(function() { table.positionViewAtRow(root.selectedRow, TableView.Contain) })
        }
    }

    readonly property int infoColumn: packetListModel.columnCount() - 1

    // Fixed widths for the narrow columns; Info takes what is left.
    function columnWidth(column) {
        const title = packetListModel.columnTitle(column)
        const widths = { "No.": 84, "Time": 110, "Delta": 96, "Source": 180,
                         "Destination": 180, "Protocol": 110, "Length": 80 }
        if (column === infoColumn) {
            let used = 0
            for (let c = 0; c < infoColumn; c++)
                used += columnWidth(c)
            return Math.max(320, table.width - used)
        }
        return widths[title] !== undefined ? widths[title] : 120
    }

    function selectRow(row) {
        if (row < 0 || row >= table.rows)
            return
        captureEngine.selectFrame(packetListModel.frameAt(row))
        table.positionViewAtRow(row, TableView.Contain)
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        HorizontalHeaderView {
            id: header
            syncView: table
            Layout.fillWidth: true
            implicitHeight: 38
            clip: true
            delegate: Rectangle {
                required property var model
                required property int column
                implicitHeight: 38
                color: Theme.surface
                Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Theme.border }
                Text {
                    anchors.fill: parent
                    anchors.leftMargin: 14
                    verticalAlignment: Text.AlignVCenter
                    text: model.display !== undefined ? model.display : ""
                    color: Theme.textMuted
                    font.pixelSize: Theme.fontBody
                    font.weight: Font.DemiBold
                    elide: Text.ElideRight
                }
            }
        }

        TableView {
            id: table
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: packetListModel
            boundsBehavior: Flickable.StopAtBounds
            reuseItems: true
            focus: true
            columnWidthProvider: function(column) { return root.columnWidth(column) }
            rowHeightProvider: function() { return Theme.rowHeight + 4 }
            onWidthChanged: forceLayout()

            ScrollBar.vertical: ScrollBar {
                policy: ScrollBar.AsNeeded
                contentItem: Rectangle {
                    implicitWidth: 8
                    radius: 4
                    color: parent.pressed ? Theme.accent : Theme.borderStrong
                }
            }

            Keys.onUpPressed: root.selectRow(Math.max(0, root.selectedRow - 1))
            Keys.onDownPressed: root.selectRow(root.selectedRow + 1)
            Keys.onPressed: (event) => {
                const page = Math.floor(table.height / (Theme.rowHeight + 4))
                if (event.key === Qt.Key_PageDown) { root.selectRow(Math.min(table.rows - 1, root.selectedRow + page)); event.accepted = true }
                else if (event.key === Qt.Key_PageUp) { root.selectRow(Math.max(0, root.selectedRow - page)); event.accepted = true }
                else if (event.key === Qt.Key_Home) { root.selectRow(0); event.accepted = true }
                else if (event.key === Qt.Key_End) { root.selectRow(table.rows - 1); event.accepted = true }
            }

            delegate: Rectangle {
                id: cell
                required property int row
                required property int column
                required property string display
                required property string protocol

                readonly property bool selected: row === root.selectedRow
                readonly property bool isProtocol: column === packetListModel.protocolColumn
                readonly property bool isInfo: column === root.infoColumn

                implicitHeight: Theme.rowHeight + 4
                color: selected ? Theme.selection : (row % 2 ? Theme.rowAlt : Theme.surface)

                // Left accent bar marks the selected row.
                Rectangle {
                    visible: cell.selected && cell.column === 0
                    width: 3; height: parent.height
                    color: Theme.accent
                }

                Text {
                    visible: !cell.isProtocol
                    anchors.fill: parent
                    anchors.leftMargin: 14
                    anchors.rightMargin: 8
                    verticalAlignment: Text.AlignVCenter
                    text: cell.display
                    color: cell.isInfo || cell.selected ? Theme.text : Theme.textMuted
                    font.family: cell.isInfo ? Theme.fontFamily : Theme.monoFamily
                    font.pixelSize: Theme.fontBody
                    elide: Text.ElideRight
                }

                // Protocol shown as a tinted pill in its family's color.
                Rectangle {
                    visible: cell.isProtocol
                    anchors.verticalCenter: parent.verticalCenter
                    x: 12
                    height: 22
                    width: Math.min(protoText.implicitWidth + 18, parent.width - 20)
                    radius: 11
                    readonly property color hue: Theme.protocolColor(cell.protocol)
                    color: Qt.rgba(hue.r, hue.g, hue.b, Theme.dark ? 0.16 : 0.12)
                    border.color: Qt.rgba(hue.r, hue.g, hue.b, 0.45)
                    Text {
                        id: protoText
                        anchors.centerIn: parent
                        width: Math.min(implicitWidth, parent.parent.width - 38)
                        text: cell.display
                        color: parent.hue
                        font.pixelSize: Theme.fontSmall
                        font.weight: Font.DemiBold
                        elide: Text.ElideRight
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    onClicked: { captureEngine.selectFrame(packetListModel.frameAt(cell.row)); table.forceActiveFocus() }
                }
            }
        }
    }
}
