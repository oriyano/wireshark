// NavButton.qml
//
// Kitsune - a navigation button with an icon and optional label.
// The checked state gets the accent outline (and a glow in dark mode).
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

AbstractButton {
    id: control
    property string iconName
    property bool wide: false

    implicitHeight: 40
    implicitWidth: wide ? 200 : content.implicitWidth + (text.length > 0 ? 28 : 20)
    hoverEnabled: true
    focusPolicy: Qt.TabFocus

    background: Rectangle {
        radius: Theme.radiusSmall + 2
        color: control.checked ? Theme.accentSoft
             : control.hovered ? Theme.surfaceHover : "transparent"
        border.width: control.checked ? 1 : 0
        border.color: Theme.accent

        // Soft outer glow for the active item in the dark theme.
        Rectangle {
            visible: control.checked && Theme.glow
            anchors.fill: parent
            anchors.margins: -3
            radius: parent.radius + 3
            color: "transparent"
            border.width: 3
            border.color: Qt.rgba(Theme.accent.r, Theme.accent.g, Theme.accent.b, 0.18)
        }
    }

    contentItem: Item {
        RowLayout {
            id: content
            anchors.verticalCenter: parent.verticalCenter
            x: control.wide ? 14 : (parent.width - implicitWidth) / 2
            spacing: 10
            Icon {
                name: control.iconName
                size: 20
                color: control.checked ? Theme.accent : Theme.textMuted
            }
            Text {
                visible: control.text.length > 0
                text: control.text
                color: control.checked ? Theme.text : Theme.textMuted
                font.pixelSize: control.wide ? Theme.fontLarge : Theme.fontLarge
                font.weight: control.checked ? Font.DemiBold : Font.Normal
            }
        }
    }
}
