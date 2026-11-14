// CaptureView.qml
//
// Kitsune - start a live capture: pick an interface, optionally a
// capture filter and a ring buffer, and go. dumpcap does the capturing;
// Kitsune reads the file as it grows.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    // Asks the window to show the packet list.
    signal showPacketsRequested()

    property string chosen: ""

    Component.onCompleted: if (captureSession.interfaces.length === 0) captureSession.refreshInterfaces()

    Connections {
        target: captureSession
        function onInterfacesChanged() {
            if (root.chosen.length === 0 && captureSession.interfaces.length > 0)
                root.chosen = root.preferredInterface()
        }
    }

    // A real network card first; "any" and loopback only if nothing else.
    function preferredInterface() {
        const list = captureSession.interfaces
        for (let i = 0; i < list.length; i++) {
            const n = list[i].name
            if (n !== "any" && n !== "lo" && !n.startsWith("bluetooth") && !n.startsWith("dbus")
                    && !n.startsWith("nflog") && !n.startsWith("nfqueue") && list[i].label.indexOf("Loopback") < 0)
                return n
        }
        return list.length > 0 ? list[0].name : ""
    }

    function megabytesText(mb) {
        return mb >= 1000 ? qsTr("%1 GB").arg((mb / 1000).toLocaleString(Qt.locale(), "f", mb >= 10000 ? 0 : 1))
                          : qsTr("%1 MB").arg(mb)
    }

    function startCapture() {
        if (root.chosen.length === 0)
            return
        captureSession.start(root.chosen)
    }

    component SectionTitle: Text {
        color: Theme.text
        font.pixelSize: Theme.fontLarge
        font.weight: Font.DemiBold
    }

    component Hint: Text {
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
        color: Theme.textMuted
        font.pixelSize: Theme.fontSmall + 1
    }

    component Field: TextField {
        implicitHeight: 36
        color: Theme.text
        placeholderTextColor: Theme.textFaint
        selectionColor: Theme.selection
        selectedTextColor: Theme.text
        font.pixelSize: Theme.fontBody
        leftPadding: 10
        background: Rectangle {
            radius: Theme.radiusSmall
            color: Theme.surfaceRaised
            border.color: parent.activeFocus ? Theme.accent : Theme.border
        }
    }

    component NumberBox: SpinBox {
        id: spin
        implicitHeight: 36
        implicitWidth: 120
        editable: true
        font.pixelSize: Theme.fontBody
        contentItem: TextInput {
            text: spin.displayText
            color: Theme.text
            font: spin.font
            horizontalAlignment: Qt.AlignHCenter
            verticalAlignment: Qt.AlignVCenter
            readOnly: !spin.editable
            validator: spin.validator
            inputMethodHints: Qt.ImhDigitsOnly
            selectByMouse: true
        }
        background: Rectangle {
            radius: Theme.radiusSmall
            color: Theme.surfaceRaised
            border.color: spin.activeFocus ? Theme.accent : Theme.border
        }
        up.indicator: Text {
            x: spin.width - width - 8
            height: spin.height
            verticalAlignment: Text.AlignVCenter
            text: "+"
            color: spin.up.pressed ? Theme.accent : Theme.textMuted
            font.pixelSize: Theme.fontLarge
        }
        down.indicator: Text {
            x: 8
            height: spin.height
            verticalAlignment: Text.AlignVCenter
            text: "−"
            color: spin.down.pressed ? Theme.accent : Theme.textMuted
            font.pixelSize: Theme.fontLarge
        }
    }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth
        clip: true

        ColumnLayout {
            width: parent.width
            spacing: 18

            // Header
            ColumnLayout {
                Layout.fillWidth: true
                Layout.margins: 24
                Layout.bottomMargin: 0
                spacing: 4
                Text {
                    text: qsTr("Capture live traffic")
                    color: Theme.text
                    font.pixelSize: 22
                    font.weight: Font.DemiBold
                }
                Hint {
                    text: qsTr("Pick the network interface to listen on. Kitsune's capture helper records the packets to a file and Kitsune shows them as they arrive, so you can filter and explore while the capture runs.")
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                spacing: 18

                // Interfaces
                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 380
                    Layout.alignment: Qt.AlignTop
                    radius: Theme.radius
                    color: Theme.window
                    border.color: Theme.border

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 10

                        RowLayout {
                            Layout.fillWidth: true
                            SectionTitle { text: qsTr("Interfaces") }
                            Item { Layout.fillWidth: true }
                            Text {
                                visible: captureSession.listingInterfaces
                                text: qsTr("Looking…")
                                color: Theme.textMuted
                                font.pixelSize: Theme.fontSmall + 1
                            }
                            ToolButton {
                                implicitWidth: 30
                                implicitHeight: 30
                                enabled: !captureSession.listingInterfaces
                                onClicked: captureSession.refreshInterfaces()
                                background: Rectangle { radius: 15; color: parent.hovered ? Theme.surfaceHover : "transparent" }
                                contentItem: Item { Icon { anchors.centerIn: parent; name: "refresh"; size: 15; color: Theme.textMuted } }
                                ToolTip.visible: hovered
                                ToolTip.text: qsTr("Look for interfaces again")
                            }
                        }

                        ListView {
                            id: ifaceList
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            spacing: 4
                            model: captureSession.interfaces
                            boundsBehavior: Flickable.StopAtBounds
                            ScrollBar.vertical: ScrollBar { }

                            delegate: Rectangle {
                                id: ifaceRow
                                required property var modelData
                                readonly property bool isChosen: root.chosen === modelData.name
                                width: ifaceList.width
                                height: 46
                                radius: Theme.radiusSmall
                                color: isChosen ? Theme.accentSoft : ifaceMouse.containsMouse ? Theme.surfaceHover : "transparent"
                                border.color: isChosen ? Theme.accent : "transparent"

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 12
                                    spacing: 10
                                    Icon {
                                        name: ifaceRow.modelData.name === "any" ? "globe"
                                            : ifaceRow.modelData.name === "lo" || ifaceRow.modelData.label.indexOf("Loopback") >= 0 ? "laptop"
                                            : "capture"
                                        size: 18
                                        color: ifaceRow.isChosen ? Theme.accent : Theme.textMuted
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 1
                                        Text {
                                            Layout.fillWidth: true
                                            text: ifaceRow.modelData.label
                                            color: Theme.text
                                            elide: Text.ElideRight
                                            font.pixelSize: Theme.fontBody
                                            font.weight: ifaceRow.isChosen ? Font.DemiBold : Font.Normal
                                        }
                                        Text {
                                            Layout.fillWidth: true
                                            visible: ifaceRow.modelData.description.length > 0
                                            text: ifaceRow.modelData.name
                                            color: Theme.textFaint
                                            elide: Text.ElideMiddle
                                            font.pixelSize: Theme.fontSmall
                                            font.family: Theme.monoFamily
                                        }
                                    }
                                }
                                MouseArea {
                                    id: ifaceMouse
                                    anchors.fill: parent
                                    hoverEnabled: true
                                    onClicked: root.chosen = ifaceRow.modelData.name
                                    onDoubleClicked: { root.chosen = ifaceRow.modelData.name; root.startCapture() }
                                }
                            }

                            Text {
                                anchors.centerIn: parent
                                width: parent.width - 32
                                visible: ifaceList.count === 0 && !captureSession.listingInterfaces
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.WordWrap
                                text: qsTr("No interfaces found. On Windows, install Npcap; on Linux and macOS, make sure the capture helper may capture.")
                                color: Theme.textMuted
                                font.pixelSize: Theme.fontBody
                            }
                        }
                    }
                }

                // Options
                Rectangle {
                    Layout.preferredWidth: 380
                    Layout.preferredHeight: 380
                    Layout.alignment: Qt.AlignTop
                    radius: Theme.radius
                    color: Theme.window
                    border.color: Theme.border

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 16
                        spacing: 10

                        SectionTitle { text: qsTr("Options") }

                        Text { text: qsTr("Capture filter"); color: Theme.text; font.pixelSize: Theme.fontBody }
                        Field {
                            Layout.fillWidth: true
                            placeholderText: qsTr("Optional, e.g. tcp port 443 or host 10.0.0.5")
                            text: captureSession.captureFilter
                            enabled: !captureSession.running
                            onTextEdited: captureSession.captureFilter = text
                        }
                        Hint {
                            text: qsTr("Decides what gets recorded at all. To hide packets you already have, use the display filter instead.")
                        }

                        Rectangle { Layout.fillWidth: true; Layout.topMargin: 4; height: 1; color: Theme.border }

                        RowLayout {
                            Layout.fillWidth: true
                            Text { text: qsTr("Ring buffer"); color: Theme.text; font.pixelSize: Theme.fontBody }
                            Item { Layout.fillWidth: true }
                            // A small switch drawn from theme tokens.
                            Rectangle {
                                id: ringSwitch
                                implicitWidth: 40
                                implicitHeight: 22
                                radius: 11
                                opacity: captureSession.running ? 0.5 : 1
                                color: captureSession.ringBuffer ? Theme.accent : Theme.border
                                Rectangle {
                                    width: 18; height: 18; radius: 9
                                    y: 2
                                    x: captureSession.ringBuffer ? parent.width - width - 2 : 2
                                    color: Theme.surface
                                    Behavior on x { NumberAnimation { duration: 120 } }
                                }
                                TapHandler {
                                    enabled: !captureSession.running
                                    onTapped: captureSession.ringBuffer = !captureSession.ringBuffer
                                }
                                Accessible.role: Accessible.CheckBox
                                Accessible.name: qsTr("Ring buffer")
                                Accessible.checked: captureSession.ringBuffer
                            }
                        }
                        Hint {
                            text: qsTr("For long captures: write to a set of files and delete the oldest, so the disk never fills up.")
                        }
                        RowLayout {
                            Layout.fillWidth: true
                            enabled: captureSession.ringBuffer && !captureSession.running
                            opacity: enabled ? 1 : 0.45
                            spacing: 8
                            NumberBox {
                                from: 2; to: 1000
                                value: captureSession.ringFiles
                                onValueModified: captureSession.ringFiles = value
                            }
                            Text { text: qsTr("files of"); color: Theme.textMuted; font.pixelSize: Theme.fontBody }
                            NumberBox {
                                from: 1; to: 100000
                                value: captureSession.ringFileMegabytes
                                onValueModified: captureSession.ringFileMegabytes = value
                            }
                            Text { text: qsTr("MB"); color: Theme.textMuted; font.pixelSize: Theme.fontBody }
                        }
                        Hint {
                            visible: captureSession.ringBuffer
                            text: qsTr("Uses at most %1 of disk.").arg(root.megabytesText(captureSession.ringFiles * captureSession.ringFileMegabytes))
                        }
                        Item { Layout.fillHeight: true }
                    }
                }
            }

            // Start / stop and live numbers
            Rectangle {
                Layout.fillWidth: true
                Layout.leftMargin: 24
                Layout.rightMargin: 24
                Layout.bottomMargin: 24
                implicitHeight: 76
                radius: Theme.radius
                color: Theme.window
                border.color: captureSession.running ? Theme.danger : Theme.border

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 18
                    anchors.rightMargin: 18
                    spacing: 18

                    Button {
                        id: startButton
                        implicitHeight: 42
                        implicitWidth: 170
                        enabled: captureSession.running ? !captureSession.stopping : root.chosen.length > 0
                        onClicked: captureSession.running ? captureSession.stop() : root.startCapture()
                        background: Rectangle {
                            radius: Theme.radiusSmall + 2
                            color: !startButton.enabled ? Theme.border
                                 : captureSession.running ? Theme.danger
                                 : startButton.hovered ? Theme.accentStrong : Theme.accent
                        }
                        contentItem: RowLayout {
                            spacing: 8
                            Item { Layout.fillWidth: true }
                            Icon {
                                name: captureSession.running ? "stop" : "play"
                                size: 15
                                color: captureSession.running ? Theme.surface : Theme.onAccent
                            }
                            Text {
                                text: captureSession.stopping ? qsTr("Stopping…")
                                    : captureSession.running ? qsTr("Stop capture") : qsTr("Start capture")
                                color: captureSession.running ? Theme.surface : Theme.onAccent
                                font.pixelSize: Theme.fontLarge
                                font.weight: Font.DemiBold
                            }
                            Item { Layout.fillWidth: true }
                        }
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text {
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                            color: captureSession.lastError.length > 0 && !captureSession.running ? Theme.danger : Theme.text
                            font.pixelSize: Theme.fontBody
                            font.weight: Font.DemiBold
                            text: captureSession.running
                                  ? qsTr("Capturing on %1").arg(captureSession.interfaceName)
                                  : captureSession.lastError.length > 0 ? captureSession.lastError
                                  : root.chosen.length > 0 ? qsTr("Ready to capture on %1").arg(root.chosen)
                                  : qsTr("Choose an interface")
                        }
                        Text {
                            Layout.fillWidth: true
                            elide: Text.ElideMiddle
                            color: Theme.textMuted
                            font.pixelSize: Theme.fontSmall + 1
                            visible: captureSession.filesWritten > 0
                            text: captureSession.ringBuffer && captureSession.filesWritten > 1
                                  ? qsTr("%1 packets · %2 dropped · file %3: %4")
                                      .arg(captureEngine.formatCount(captureSession.packets))
                                      .arg(captureEngine.formatCount(captureSession.drops))
                                      .arg(captureSession.filesWritten).arg(captureSession.currentFile)
                                  : qsTr("%1 packets · %2 dropped · %3")
                                      .arg(captureEngine.formatCount(captureSession.packets))
                                      .arg(captureEngine.formatCount(captureSession.drops))
                                      .arg(captureSession.currentFile)
                        }
                    }

                    Button {
                        id: viewButton
                        visible: captureEngine.hasFile
                        implicitHeight: 38
                        text: qsTr("View packets")
                        onClicked: root.showPacketsRequested()
                        background: Rectangle {
                            radius: Theme.radiusSmall
                            color: viewButton.hovered ? Theme.surfaceHover : Theme.surfaceRaised
                            border.color: Theme.borderStrong
                        }
                        contentItem: Text {
                            text: viewButton.text
                            color: Theme.text
                            font.pixelSize: Theme.fontBody
                            horizontalAlignment: Text.AlignHCenter
                            verticalAlignment: Text.AlignVCenter
                            leftPadding: 10
                            rightPadding: 10
                        }
                    }
                }
            }
        }
    }
}
