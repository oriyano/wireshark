// TopBar.qml
//
// Kitsune - brand mark, main navigation and global actions.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Shapes

Rectangle {
    id: root
    property string currentView
    signal viewRequested(string view)
    signal openRequested()

    implicitHeight: 60
    radius: Theme.radius
    color: Theme.surface
    border.color: Theme.border

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 16
        anchors.rightMargin: 12
        spacing: 6

        // Brand: a stylized fox head in the accent color.
        Item {
            Layout.preferredWidth: 34
            Layout.preferredHeight: 34
            Shape {
                anchors.fill: parent
                layer.enabled: true
                layer.samples: 4
                ShapePath {
                    scale: Qt.size(34 / 24, 34 / 24)
                    strokeColor: "transparent"
                    fillGradient: LinearGradient {
                        x1: 0; y1: 0; x2: 24; y2: 24
                        GradientStop { position: 0.0; color: Theme.accent }
                        GradientStop { position: 1.0; color: Qt.darker(Theme.accentStrong, 1.25) }
                    }
                    PathSvg { path: "M2 3l6 5h8l6-5-1.5 9.5L12 21 3.5 12.5z" }
                }
                ShapePath {
                    scale: Qt.size(34 / 24, 34 / 24)
                    strokeColor: "transparent"
                    fillColor: Theme.surface
                    PathSvg { path: "M7.5 11.5l3 1.2-2.4 1.1z M16.5 11.5l-3 1.2 2.4 1.1z M10.6 17h2.8L12 18.6z" }
                }
            }
        }

        ColumnLayout {
            spacing: -2
            Layout.rightMargin: 24
            Text {
                text: "Kitsune"
                color: Theme.text
                font.pixelSize: Theme.fontTitle
                font.weight: Font.DemiBold
            }
            Text {
                text: qsTr("Network analysis, explained")
                color: Theme.textMuted
                font.pixelSize: 11
            }
        }

        Repeater {
            model: [
                { view: "capture",  label: qsTr("Capture"),       icon: "capture" },
                { view: "packets",  label: qsTr("Analyze"),       icon: "analyze" },
                { view: "map",      label: qsTr("Network Map"),   icon: "map" },
                { view: "stats",    label: qsTr("Statistics"),    icon: "stats" },
                { view: "convo",    label: qsTr("Conversations"), icon: "convo" },
                { view: "expert",   label: qsTr("Expert Info"),   icon: "expert" }
            ]
            delegate: NavButton {
                required property var modelData
                text: modelData.label
                iconName: modelData.icon
                checked: root.currentView === modelData.view
                onClicked: root.viewRequested(modelData.view)
            }
        }

        Item { Layout.fillWidth: true }

        NavButton {
            iconName: "folder"
            text: qsTr("Open")
            onClicked: root.openRequested()
        }
        ThemeSwitcher { }
        NavButton {
            iconName: "help"
            ToolTip.visible: hovered
            ToolTip.text: qsTr("Help")
        }
    }
}
