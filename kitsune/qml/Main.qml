// Main.qml
//
// Kitsune - main window: top navigation, file bar, side bar and the
// active view.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts

ApplicationWindow {
    id: window
    width: 1440
    height: 860
    minimumWidth: 960
    minimumHeight: 600
    visible: true
    title: captureEngine.hasFile ? captureEngine.fileName + " — Kitsune" : "Kitsune"
    color: Theme.window
    font.family: Theme.fontFamily
    font.pixelSize: Theme.fontBody

    // Which view fills the main area: "packets", "map", "stats", "graphs".
    property string currentView: "packets"

    function openCapture() { openDialog.open() }

    FileDialog {
        id: openDialog
        title: qsTr("Open a capture file")
        nameFilters: [qsTr("Capture files (*.pcap *.pcapng *.cap *.pcap.gz *.pcapng.gz *.pcapng.zst)"),
                      qsTr("All files (*)")]
        onAccepted: captureEngine.openFile(selectedFile)
    }

    Shortcut { sequence: StandardKey.Open; onActivated: window.openCapture() }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.gap
        spacing: Theme.gap

        TopBar {
            Layout.fillWidth: true
            currentView: window.currentView
            onViewRequested: (view) => window.currentView = view
            onOpenRequested: window.openCapture()
        }

        FileInfoBar {
            Layout.fillWidth: true
            onOpenRequested: window.openCapture()
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: Theme.gap

            SideBar {
                Layout.preferredWidth: 220
                Layout.fillHeight: true
                currentView: window.currentView
                onViewRequested: (view) => window.currentView = view
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.fillHeight: true
                radius: Theme.radius
                color: Theme.surface
                border.color: Theme.border
                clip: true

                StackLayout {
                    anchors.fill: parent
                    anchors.margins: 1
                    currentIndex: !captureEngine.hasFile ? 0
                                  : window.currentView === "packets" ? 1 : 2

                    WelcomeView { onOpenRequested: window.openCapture() }

                    PacketListView { }

                    PlaceholderView { view: window.currentView }
                }
            }
        }
    }

    // Errors slide in at the bottom and dismiss themselves.
    Rectangle {
        id: toast
        property string message
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: visible ? 28 : -height
        width: Math.min(toastText.implicitWidth + 48, parent.width - 64)
        height: 44
        radius: Theme.radius
        color: Theme.surfaceRaised
        border.color: Theme.danger
        visible: message.length > 0

        Text {
            id: toastText
            anchors.centerIn: parent
            width: parent.width - 32
            text: toast.message
            color: Theme.text
            elide: Text.ElideRight
            horizontalAlignment: Text.AlignHCenter
            font.pixelSize: Theme.fontBody
        }

        Timer { id: toastTimer; interval: 6000; onTriggered: toast.message = "" }

        Connections {
            target: captureEngine
            function onErrorOccurred(message) {
                toast.message = message
                toastTimer.restart()
            }
        }
    }
}
