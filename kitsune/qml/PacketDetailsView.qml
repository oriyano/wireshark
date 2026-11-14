// PacketDetailsView.qml
//
// Kitsune - the selected packet, one protocol layer per branch.
// Selecting a field highlights its bytes; the filter button next to a
// field shows only the packets that share its value.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    color: Theme.surface

    // The selected field's byte range, for the bytes view.
    property int selectedRow: -1
    property int highlightStart: -1
    property int highlightLength: 0
    property string selectedFilter: ""

    function select(row) {
        if (row < 0 || row >= tree.rows)
            return
        selectedRow = row
        tree.positionViewAtRow(row, TableView.Contain)
        tree.forceActiveFocus()
    }

    // Expanding or collapsing a branch moves the rows below it.
    function toggle(row) {
        const before = tree.rows
        tree.toggleExpanded(row)
        if (selectedRow > row)
            selectedRow += tree.rows - before
    }

    Connections {
        target: packetDetailsModel
        function onDetailsChanged() {
            root.selectedRow = -1
            root.highlightStart = -1
            root.highlightLength = 0
            root.selectedFilter = ""
            // Open the innermost layer: usually what the packet is about.
            Qt.callLater(function() {
                if (tree.rows > 0)
                    tree.expand(tree.rows - 1)
            })
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        // Header
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 38
            color: Theme.surface
            Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Theme.border }
            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 14
                anchors.rightMargin: 14
                spacing: 8
                Icon { name: "details"; size: 16; color: Theme.textMuted }
                Text {
                    text: packetDetailsModel.frame > 0 ? qsTr("Packet %1").arg(packetDetailsModel.frame) : qsTr("Packet details")
                    color: Theme.textMuted
                    font.pixelSize: Theme.fontBody
                    font.weight: Font.DemiBold
                }
                Item { Layout.fillWidth: true }
                Text {
                    visible: root.selectedFilter.length > 0
                    text: root.selectedFilter
                    color: Theme.textFaint
                    font.family: Theme.monoFamily
                    font.pixelSize: Theme.fontSmall
                    elide: Text.ElideMiddle
                    Layout.maximumWidth: root.width * 0.55
                }
            }
        }

        Text {
            visible: packetDetailsModel.frame <= 0
            Layout.fillWidth: true
            Layout.fillHeight: true
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            text: qsTr("Select a packet to see its layers")
            color: Theme.textFaint
            font.pixelSize: Theme.fontBody
        }

        TreeView {
            id: tree
            visible: packetDetailsModel.frame > 0
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            model: packetDetailsModel
            boundsBehavior: Flickable.StopAtBounds
            columnWidthProvider: function() { return tree.width }
            onWidthChanged: forceLayout()

            ScrollBar.vertical: ScrollBar {
                policy: ScrollBar.AsNeeded
                contentItem: Rectangle { implicitWidth: 8; radius: 4; color: Theme.borderStrong }
            }

            Keys.onUpPressed: root.select(root.selectedRow - 1)
            Keys.onDownPressed: root.select(root.selectedRow + 1)
            Keys.onRightPressed: if (root.selectedRow >= 0 && !tree.isExpanded(root.selectedRow)) root.toggle(root.selectedRow)
            Keys.onLeftPressed: if (root.selectedRow >= 0 && tree.isExpanded(root.selectedRow)) root.toggle(root.selectedRow)
            Keys.onReturnPressed: if (root.selectedFilter.length > 0) captureEngine.applyFilter(root.selectedFilter)

            delegate: Rectangle {
                id: node
                required property TreeView treeView
                required property bool isTreeNode
                required property bool expanded
                required property int hasChildren
                required property int depth
                required property int row
                required property string display
                required property string filter
                required property int byteStart
                required property int byteLength
                required property int severity
                required property bool isProtocol

                readonly property bool selected: row === root.selectedRow
                readonly property color severityColor: severity >= 4 ? Theme.danger
                                                     : severity === 3 ? Theme.warning
                                                     : severity === 2 ? Theme.accent : Theme.text

                implicitWidth: tree.width
                implicitHeight: 26
                color: selected ? Theme.selection : hover.hovered ? Theme.surfaceHover : "transparent"

                onSelectedChanged: if (selected) {
                    root.highlightStart = byteStart
                    root.highlightLength = byteLength
                    root.selectedFilter = filter
                }

                HoverHandler { id: hover }

                Rectangle {
                    visible: node.selected
                    width: 3; height: parent.height
                    color: Theme.accent
                }

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 8 + node.depth * 18
                    anchors.rightMargin: 8
                    spacing: 4

                    Item {
                        implicitWidth: 18
                        implicitHeight: 18
                        Icon {
                            anchors.centerIn: parent
                            visible: node.hasChildren
                            name: node.expanded ? "chevronDown" : "chevronRight"
                            size: 14
                            color: Theme.textMuted
                        }
                        TapHandler { enabled: node.hasChildren; onTapped: root.toggle(node.row) }
                    }

                    Text {
                        Layout.fillWidth: true
                        text: node.display
                        color: node.severity >= 2 ? node.severityColor
                             : node.isProtocol || node.selected ? Theme.text : Theme.textMuted
                        font.family: node.isProtocol ? Theme.fontFamily : Theme.monoFamily
                        font.pixelSize: Theme.fontBody
                        font.weight: node.isProtocol ? Font.DemiBold : Font.Normal
                        elide: Text.ElideRight
                    }

                    // Show only packets like this one.
                    Rectangle {
                        visible: node.filter.length > 0 && (node.selected || hover.hovered)
                        implicitWidth: filterRow.implicitWidth + 14
                        implicitHeight: 20
                        radius: 10
                        color: filterTap.hovered ? Theme.accent : Theme.accentSoft
                        RowLayout {
                            id: filterRow
                            anchors.centerIn: parent
                            spacing: 4
                            Icon { name: "filter"; size: 11; color: filterTap.hovered ? Theme.onAccent : Theme.accent }
                            Text {
                                text: qsTr("Filter")
                                font.pixelSize: 11
                                font.weight: Font.DemiBold
                                color: filterTap.hovered ? Theme.onAccent : Theme.accent
                            }
                        }
                        HoverHandler { id: filterTap }
                        TapHandler { onTapped: captureEngine.applyFilter(node.filter) }
                        ToolTip.visible: filterTap.hovered
                        ToolTip.text: qsTr("Show only packets where %1").arg(node.filter)
                    }
                }

                TapHandler {
                    onTapped: root.select(node.row)
                    onDoubleTapped: if (node.hasChildren) root.toggle(node.row)
                }
            }
        }
    }
}
