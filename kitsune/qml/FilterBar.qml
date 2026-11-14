// FilterBar.qml
//
// Kitsune - the display filter. The engine checks the text as you
// type and explains mistakes in plain English; Enter applies it.
// Filtering runs on the engine thread, so the bar shows progress and
// can cancel a slow filter.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: root
    spacing: 6

    // "empty", "checking", "valid" or "invalid"
    property string state_: "empty"
    property string message: ""
    property int errorStart: -1
    property int errorLength: 0
    property alias text: field.text
    property string lastSynced: ""

    function apply() {
        if (root.state_ === "invalid")
            return
        captureEngine.applyFilter(field.text)
    }

    function setText(text) {
        field.text = text
        check()
    }

    function check() {
        if (field.text.trim().length === 0) {
            root.state_ = "empty"
            root.message = ""
            return
        }
        root.state_ = "checking"
        checkTimer.restart()
    }

    Timer {
        id: checkTimer
        interval: 180
        onTriggered: captureEngine.checkFilter(field.text)
    }

    Connections {
        target: captureEngine
        function onFilterChecked(text, valid, message, errorStart, errorLength) {
            if (text !== field.text)
                return
            root.state_ = valid ? "valid" : "invalid"
            root.message = message
            root.errorStart = errorStart
            root.errorLength = errorLength
        }
        // Keep the bar in step when something else applies a filter,
        // such as "Apply as filter" in the packet details.
        function onFilterChanged() {
            if (!captureEngine.filtering && captureEngine.filterText !== root.lastSynced) {
                root.lastSynced = captureEngine.filterText
                if (field.text !== captureEngine.filterText)
                    root.setText(captureEngine.filterText)
            }
        }
    }

    readonly property color stateColor: state_ === "valid" ? Theme.success
                                      : state_ === "invalid" ? Theme.danger : Theme.border

    RowLayout {
        Layout.fillWidth: true
        spacing: 10

        Rectangle {
            Layout.fillWidth: true
            implicitHeight: 40
            radius: Theme.radiusSmall
            color: Theme.surfaceRaised
            border.width: field.activeFocus || root.state_ === "invalid" || root.state_ === "valid" ? 1.5 : 1
            border.color: root.state_ === "empty" || root.state_ === "checking"
                          ? (field.activeFocus ? Theme.accent : Theme.border) : root.stateColor

            RowLayout {
                anchors.fill: parent
                anchors.leftMargin: 12
                anchors.rightMargin: 6
                spacing: 8

                Icon { name: "filter"; size: 16; color: Theme.textMuted }

                TextField {
                    id: field
                    Layout.fillWidth: true
                    placeholderText: qsTr("Display filter, e.g. http or ip.addr == 192.168.1.1 and tcp.port == 443")
                    placeholderTextColor: Theme.textFaint
                    color: Theme.text
                    selectionColor: Theme.selection
                    selectedTextColor: Theme.text
                    // Not the mono font: coding ligatures would turn == into one glyph.
                    font.family: Theme.fontFamily
                    font.pixelSize: Theme.fontBody
                    background: null
                    leftPadding: 0
                    enabled: captureEngine.hasFile && !captureEngine.loading
                    onTextEdited: root.check()
                    onAccepted: root.apply()
                    Keys.onEscapePressed: {
                        if (captureEngine.filtering) captureEngine.cancelFilter()
                        else if (text.length > 0) { root.setText(""); root.apply() }
                    }

                    // Underline the part of the filter the engine objected to.
                    Rectangle {
                        visible: root.state_ === "invalid" && root.errorStart >= 0 && field.text.length > 0
                        readonly property rect startRect: field.positionToRectangle(Math.min(root.errorStart, field.text.length))
                        readonly property rect endRect: field.positionToRectangle(Math.min(root.errorStart + Math.max(1, root.errorLength), field.text.length))
                        x: field.leftPadding + startRect.x
                        y: field.topPadding + startRect.y + startRect.height + 1
                        width: Math.max(6, endRect.x - startRect.x)
                        height: 2
                        radius: 1
                        color: Theme.danger
                    }
                }

                // Valid / invalid badge
                Rectangle {
                    visible: root.state_ === "valid" || root.state_ === "invalid"
                    implicitWidth: badgeRow.implicitWidth + 16
                    implicitHeight: 24
                    radius: 12
                    color: Qt.rgba(root.stateColor.r, root.stateColor.g, root.stateColor.b, 0.14)
                    RowLayout {
                        id: badgeRow
                        anchors.centerIn: parent
                        spacing: 4
                        Icon { name: root.state_ === "valid" ? "check" : "warning"; size: 13; color: root.stateColor }
                        Text {
                            text: root.state_ === "valid" ? qsTr("Valid") : qsTr("Invalid")
                            color: root.stateColor
                            font.pixelSize: Theme.fontSmall
                            font.weight: Font.DemiBold
                        }
                    }
                }

                // Clear
                ToolButton {
                    visible: field.text.length > 0
                    implicitWidth: 28
                    implicitHeight: 28
                    onClicked: { root.setText(""); root.apply() }
                    background: Rectangle { radius: 14; color: parent.hovered ? Theme.surfaceHover : "transparent" }
                    contentItem: Item { Icon { anchors.centerIn: parent; name: "close"; size: 14; color: Theme.textMuted } }
                    ToolTip.visible: hovered
                    ToolTip.text: qsTr("Clear the filter")
                }
            }
        }

        Button {
            id: applyButton
            implicitHeight: 40
            implicitWidth: 96
            enabled: captureEngine.hasFile && !captureEngine.loading && root.state_ !== "invalid"
            onClicked: captureEngine.filtering ? captureEngine.cancelFilter() : root.apply()
            background: Rectangle {
                radius: Theme.radiusSmall
                color: captureEngine.filtering ? Theme.surfaceRaised
                     : !applyButton.enabled ? Theme.border
                     : applyButton.hovered ? Theme.accentStrong : Theme.accent
                border.color: captureEngine.filtering ? Theme.borderStrong : "transparent"
            }
            contentItem: Text {
                text: captureEngine.filtering ? qsTr("Cancel") : qsTr("Apply")
                horizontalAlignment: Text.AlignHCenter
                verticalAlignment: Text.AlignVCenter
                color: captureEngine.filtering ? Theme.text : Theme.onAccent
                font.pixelSize: Theme.fontBody
                font.weight: Font.DemiBold
            }
        }
    }

    // Status line: the plain-English error, filtering progress, or the
    // number of packets shown.
    RowLayout {
        Layout.fillWidth: true
        Layout.leftMargin: 4
        spacing: 10
        visible: captureEngine.hasFile && !captureEngine.loading

        ProgressBar {
            id: progress
            visible: captureEngine.filtering
            Layout.preferredWidth: 160
            value: captureEngine.filterProgress
            background: Rectangle { implicitHeight: 4; radius: 2; color: Theme.border }
            contentItem: Item {
                Rectangle { width: progress.visualPosition * parent.width; height: parent.height; radius: 2; color: Theme.accent }
            }
        }

        Text {
            Layout.fillWidth: true
            elide: Text.ElideRight
            font.pixelSize: Theme.fontSmall
            color: root.state_ === "invalid" ? Theme.danger : Theme.textMuted
            text: captureEngine.filtering
                  ? qsTr("Filtering… %1%").arg(Math.round(captureEngine.filterProgress * 100))
                  : root.state_ === "invalid" ? root.message
                  : captureEngine.filterText.length > 0
                    ? qsTr("Showing %1 of %2 packets that match “%3” (%4 ms)")
                        .arg(captureEngine.formatCount(captureEngine.displayedCount))
                        .arg(captureEngine.formatCount(captureEngine.packetCount))
                        .arg(captureEngine.filterText)
                        .arg(captureEngine.filterTimeMs)
                    : qsTr("Showing all %1 packets").arg(captureEngine.formatCount(captureEngine.packetCount))
        }
    }
}
