// PacketBytesView.qml
//
// Kitsune - the selected packet's raw bytes, 16 to a row, in hex and
// ASCII. The bytes of the field selected in the details view light up.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Rectangle {
    id: root
    color: Theme.surface

    property int highlightStart: -1
    property int highlightLength: 0

    function highlighted(offset) {
        return highlightStart >= 0 && offset >= highlightStart && offset < highlightStart + highlightLength
    }

    // Bring the highlighted bytes into view.
    onHighlightStartChanged: if (highlightStart >= 0)
        list.positionViewAtIndex(Math.floor(highlightStart / 16), ListView.Contain)

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

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
                Icon { name: "bytes"; size: 16; color: Theme.textMuted }
                Text {
                    text: qsTr("Bytes")
                    color: Theme.textMuted
                    font.pixelSize: Theme.fontBody
                    font.weight: Font.DemiBold
                }
                Item { Layout.fillWidth: true }
                Text {
                    text: root.highlightStart >= 0 && root.highlightLength > 0
                          ? qsTr("%1 selected at offset %2").arg(root.highlightLength === 1 ? qsTr("1 byte") : qsTr("%1 bytes").arg(root.highlightLength))
                                                             .arg("0x" + root.highlightStart.toString(16).padStart(4, "0"))
                          : packetBytesModel.byteCount > 0 ? qsTr("%1 bytes").arg(packetBytesModel.byteCount) : ""
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontSmall
                }
            }
        }

        ListView {
            id: list
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.topMargin: 6
            clip: true
            model: packetBytesModel
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar {
                policy: ScrollBar.AsNeeded
                contentItem: Rectangle { implicitWidth: 8; radius: 4; color: Theme.borderStrong }
            }

            delegate: RowLayout {
                id: line
                required property string offset
                required property var hex
                required property string ascii
                required property int rowStart
                height: 22
                spacing: 14
                x: 14

                Text {
                    text: line.offset
                    color: Theme.textFaint
                    font.family: Theme.monoFamily
                    font.pixelSize: Theme.fontBody
                }

                Row {
                    spacing: 0
                    Repeater {
                        model: line.hex
                        delegate: Rectangle {
                            required property string modelData
                            required property int index
                            readonly property bool on: root.highlighted(line.rowStart + index)
                            width: hexText.implicitWidth + (index === 7 ? 14 : 7)
                            height: 20
                            color: "transparent"
                            Rectangle {
                                visible: parent.on
                                x: -2
                                width: hexText.implicitWidth + 4 + (index !== 15 && root.highlighted(line.rowStart + index + 1) ? (index === 7 ? 10 : 3) : 0)
                                height: parent.height
                                radius: 3
                                color: Theme.accentSoft
                            }
                            Text {
                                id: hexText
                                anchors.verticalCenter: parent.verticalCenter
                                text: parent.modelData
                                color: parent.on ? Theme.accent : Theme.text
                                font.family: Theme.monoFamily
                                font.pixelSize: Theme.fontBody
                                font.weight: parent.on ? Font.DemiBold : Font.Normal
                            }
                        }
                    }
                }

                Row {
                    spacing: 0
                    Repeater {
                        model: line.ascii.length
                        delegate: Text {
                            required property int index
                            readonly property bool on: root.highlighted(line.rowStart + index)
                            text: line.ascii.charAt(index)
                            color: on ? Theme.accent : Theme.textMuted
                            font.family: Theme.monoFamily
                            font.pixelSize: Theme.fontBody
                            font.weight: on ? Font.DemiBold : Font.Normal
                        }
                    }
                }
            }
        }
    }
}
