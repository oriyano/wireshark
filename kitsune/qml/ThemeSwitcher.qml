// ThemeSwitcher.qml
//
// Kitsune - a three-way switch for system colors, light and dark.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls

Rectangle {
    id: root
    implicitWidth: row.implicitWidth + 8
    implicitHeight: 36
    radius: height / 2
    color: Theme.window
    border.color: Theme.border

    Row {
        id: row
        anchors.centerIn: parent
        spacing: 2

        Repeater {
            model: [
                { mode: 0, icon: "monitor", tip: qsTr("System colors") },
                { mode: 1, icon: "sun",     tip: qsTr("Light theme") },
                { mode: 2, icon: "moon",    tip: qsTr("Dark theme") }
            ]
            delegate: AbstractButton {
                required property var modelData
                width: 32
                height: 28
                hoverEnabled: true
                checked: kitsuneSettings.themeMode === modelData.mode
                onClicked: kitsuneSettings.themeMode = modelData.mode
                ToolTip.visible: hovered
                ToolTip.text: modelData.tip
                Accessible.name: modelData.tip
                background: Rectangle {
                    radius: height / 2
                    color: parent.checked ? Theme.accentSoft : parent.hovered ? Theme.surfaceHover : "transparent"
                    border.width: parent.checked ? 1 : 0
                    border.color: Theme.accent
                }
                contentItem: Item {
                    Icon {
                        anchors.centerIn: parent
                        name: modelData.icon
                        size: 16
                        color: parent.parent.checked ? Theme.accent : Theme.textMuted
                    }
                }
            }
        }
    }
}
