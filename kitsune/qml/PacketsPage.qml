// PacketsPage.qml
//
// Kitsune - the analysis workspace: filter bar, packet list, and the
// selected packet's layers and bytes underneath.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    // "all" shows every pane; "details" or "bytes" gives that pane the
    // whole lower half (the side bar's Packet Details / Bytes entries).
    property string focusPane: "all"
    property alias filterBar: filterBar
    property alias details: details

    component Handle: Rectangle {
        implicitWidth: 6
        implicitHeight: 6
        color: SplitHandle.pressed ? Theme.accent : SplitHandle.hovered ? Theme.borderStrong : Theme.border
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        FilterBar {
            id: filterBar
            Layout.fillWidth: true
            Layout.margins: 12
            Layout.bottomMargin: 6
        }

        Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: Theme.border }

        SplitView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            orientation: Qt.Vertical
            handle: Handle { }

            PacketListView {
                SplitView.fillHeight: true
                SplitView.minimumHeight: 140
            }

            SplitView {
                SplitView.preferredHeight: root.height * 0.42
                SplitView.minimumHeight: 120
                orientation: Qt.Horizontal
                handle: Handle { }

                PacketDetailsView {
                    id: details
                    visible: root.focusPane !== "bytes"
                    SplitView.fillWidth: true
                    SplitView.minimumWidth: 260
                }
                PacketBytesView {
                    visible: root.focusPane !== "details"
                    SplitView.preferredWidth: root.focusPane === "bytes" ? root.width : 640
                    SplitView.minimumWidth: 260
                    highlightStart: details.highlightStart
                    highlightLength: details.highlightLength
                }
            }
        }
    }
}
