// TopologyView.qml
//
// Kitsune - the network at a glance: the gateway's network in the
// middle, the Internet to its left, every other subnet around it.
// Click a subnet to see its hosts.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    signal subnetChosen(string cidr)

    property int revision: 0
    property int namesRevision: 0
    Connections { target: subnetModel; function onCountChanged() { root.revision++ } }
    Connections { target: kitsuneSettings; function onSubnetNamesChanged() { root.namesRevision++ } }

    readonly property var gateway: revision >= 0 ? subnetModel.gateway() : ({})
    readonly property var totals: revision >= 0 ? subnetModel.totals() : ({})
    readonly property var protocols: revision >= 0 ? subnetModel.topProtocols(5) : []

    // Split the subnets into the center (the gateway's), the Internet,
    // and the ring around the center.
    readonly property var layout: {
        revision
        let center = null, internet = null
        const ring = []
        for (let i = 0; i < subnetModel.count; i++) {
            const idx = subnetModel.index(i, 0)
            const s = {
                cidr: subnetModel.data(idx, Qt.UserRole + 1),
                suggested: subnetModel.data(idx, Qt.UserRole + 2),
                hosts: subnetModel.data(idx, Qt.UserRole + 3)
            }
            if (s.cidr === "Internet") internet = s
            else if (gateway.subnet && s.cidr === gateway.subnet) center = s
            else ring.push(s)
        }
        if (!center && ring.length > 0) center = ring.shift()
        return { center: center, internet: internet, ring: ring }
    }

    function label(s) {
        namesRevision
        if (!s) return ""
        const custom = kitsuneSettings.subnetName(s.cidr)
        return custom.length > 0 ? custom : (s.suggested || s.cidr)
    }

    function iconFor(s) {
        const name = (s && s.suggested) || ""
        if (name === "Workstations") return "laptop"
        if (name === "Servers") return "server"
        if (name === "IoT devices") return "chip"
        if (name === "Core") return "router"
        return "map"
    }

    // One hue per ring position, tuned for each theme.
    function hue(i) {
        const d = Theme.dark || (Theme.system && kitsuneSettings.systemPrefersDark)
        const darkHues = ["#22d3ee", "#34d399", "#fbbf24", "#a78bfa", "#2dd4bf", "#f472b6", "#60a5fa", "#fb923c"]
        const lightHues = ["#0e7490", "#047857", "#b45309", "#6d28d9", "#0f766e", "#be185d", "#1d4ed8", "#c2410c"]
        const set = d ? darkHues : lightHues
        return set[i % set.length]
    }

    component SubnetCard: Rectangle {
        id: card
        property var subnet
        property color tint: Theme.accent
        property bool center: false
        width: center ? 210 : 200
        height: center ? 92 : 78
        radius: center ? 46 : Theme.radius
        color: hoverArea.hovered ? Qt.tint(Theme.surfaceRaised, Qt.rgba(tint.r, tint.g, tint.b, 0.16))
                                 : Qt.tint(Theme.surfaceRaised, Qt.rgba(tint.r, tint.g, tint.b, 0.07))
        border.color: Qt.rgba(tint.r, tint.g, tint.b, hoverArea.hovered ? 0.9 : 0.55)
        border.width: center ? 2 : 1.5

        HoverHandler { id: hoverArea; cursorShape: Qt.PointingHandCursor }
        TapHandler { onTapped: if (card.subnet) root.subnetChosen(card.subnet.cidr) }

        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: card.center ? 22 : 14
            anchors.rightMargin: 14
            spacing: 12
            Icon { name: card.center ? "router" : root.iconFor(card.subnet); size: card.center ? 30 : 26; color: card.tint }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 1
                Text {
                    Layout.fillWidth: true
                    text: card.center && root.gateway.name ? root.gateway.name : root.label(card.subnet)
                    color: Theme.text
                    font.pixelSize: Theme.fontBody + 1
                    font.weight: Font.DemiBold
                    elide: Text.ElideRight
                }
                Text {
                    Layout.fillWidth: true
                    text: card.subnet ? card.subnet.cidr : ""
                    color: Theme.textMuted
                    font.family: Theme.monoFamily
                    font.pixelSize: Theme.fontSmall
                    elide: Text.ElideRight
                }
                Text {
                    text: card.subnet ? (card.subnet.hosts === 1 ? qsTr("1 host") : qsTr("%1 hosts").arg(card.subnet.hosts)) : ""
                    color: Theme.textMuted
                    font.pixelSize: Theme.fontSmall
                }
            }
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        // ---------------------------------------------------------- canvas
        Item {
            id: stage
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true

            readonly property real cx: width * (root.layout.internet ? 0.56 : 0.5)
            readonly property real cy: height / 2
            readonly property real rx: Math.max(160, Math.min(width * 0.32, 340))
            readonly property real ry: Math.max(120, Math.min(height * 0.36, 260))
            readonly property real internetX: Math.max(70, cx - rx - 190)

            function ringPos(i, n) {
                // Spread around the right-hand side and top/bottom, leaving
                // the left for the Internet link.
                const start = root.layout.internet ? -Math.PI * 0.62 : -Math.PI / 2
                const span = root.layout.internet ? Math.PI * 1.24 : Math.PI * 2
                const step = root.layout.internet ? (n > 1 ? span / (n - 1) : 0) : span / Math.max(1, n)
                const a = n === 1 && root.layout.internet ? 0 : start + i * step
                return Qt.point(cx + rx * Math.cos(a), cy + ry * Math.sin(a))
            }

            onWidthChanged: links.requestPaint()
            onHeightChanged: links.requestPaint()

            Canvas {
                id: links
                anchors.fill: parent
                property color lineColor: Theme.borderStrong
                property color glowColor: Theme.accent
                onLineColorChanged: requestPaint()
                Connections { target: root; function onLayoutChanged() { links.requestPaint() } }
                onPaint: {
                    const ctx = getContext("2d")
                    ctx.reset()
                    ctx.lineWidth = 2
                    ctx.strokeStyle = Theme.glow ? Qt.rgba(glowColor.r, glowColor.g, glowColor.b, 0.55) : lineColor
                    const ring = root.layout.ring
                    for (let i = 0; i < ring.length; i++) {
                        const p = stage.ringPos(i, ring.length)
                        // Elbow connectors, as in a network diagram.
                        ctx.beginPath()
                        ctx.moveTo(stage.cx, stage.cy)
                        ctx.lineTo(p.x, stage.cy + (p.y - stage.cy) * 0.35)
                        ctx.lineTo(p.x, p.y)
                        ctx.stroke()
                    }
                    if (root.layout.internet) {
                        ctx.beginPath()
                        ctx.moveTo(stage.internetX, stage.cy)
                        ctx.lineTo(stage.cx, stage.cy)
                        ctx.stroke()
                    }
                }
            }

            // Internet
            Item {
                visible: !!root.layout.internet
                width: 150
                height: 120
                x: stage.internetX - width / 2
                y: stage.cy - height / 2
                HoverHandler { id: netHover; cursorShape: Qt.PointingHandCursor }
                TapHandler { onTapped: root.subnetChosen("Internet") }
                Rectangle {
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: 72; height: 72; radius: 36
                    color: Theme.surfaceRaised
                    border.color: netHover.hovered ? Theme.accent : Theme.borderStrong
                    border.width: 1.5
                    Icon { anchors.centerIn: parent; name: "globe"; size: 36; color: Theme.accent; strokeWidth: 1.5 }
                }
                Column {
                    anchors.bottom: parent.bottom
                    anchors.horizontalCenter: parent.horizontalCenter
                    Text { anchors.horizontalCenter: parent.horizontalCenter; text: qsTr("Internet"); color: Theme.text; font.weight: Font.DemiBold; font.pixelSize: Theme.fontBody }
                    Text {
                        anchors.horizontalCenter: parent.horizontalCenter
                        text: root.layout.internet ? qsTr("%1 hosts").arg(root.layout.internet.hosts) : ""
                        color: Theme.textMuted; font.pixelSize: Theme.fontSmall
                    }
                }
            }

            // The ring
            Repeater {
                model: root.layout.ring
                delegate: SubnetCard {
                    required property var modelData
                    required property int index
                    subnet: modelData
                    tint: root.hue(index + 1)
                    readonly property point p: stage.ringPos(index, root.layout.ring.length)
                    x: p.x - width / 2
                    y: p.y - height / 2
                }
            }

            // The center: the gateway's network
            SubnetCard {
                visible: !!root.layout.center
                center: true
                subnet: root.layout.center
                tint: root.hue(0)
                x: stage.cx - width / 2
                y: stage.cy - height / 2
            }

            Text {
                anchors.left: parent.left
                anchors.bottom: parent.bottom
                anchors.margins: 14
                text: qsTr("Built from the traffic in this capture. Click a network to see its hosts.")
                color: Theme.textFaint
                font.pixelSize: Theme.fontSmall
            }
        }

        Rectangle { Layout.fillHeight: true; implicitWidth: 1; color: Theme.border }

        // ---------------------------------------------------------- summary
        ColumnLayout {
            Layout.preferredWidth: 300
            Layout.maximumWidth: 300
            Layout.fillWidth: false
            Layout.fillHeight: true
            Layout.margins: 18
            spacing: 16

            RowLayout {
                spacing: 12
                Icon { name: "map"; size: 30; color: Theme.accent }
                ColumnLayout {
                    spacing: 0
                    Text { text: qsTr("Network summary"); color: Theme.text; font.pixelSize: 17; font.weight: Font.DemiBold }
                    Text {
                        text: root.gateway.ipv4 ? qsTr("Gateway %1").arg(root.gateway.ipv4) : qsTr("No gateway seen")
                        color: Theme.textMuted; font.pixelSize: Theme.fontSmall
                    }
                }
            }

            GridLayout {
                Layout.fillWidth: true
                columns: 4
                columnSpacing: 6
                Repeater {
                    model: [
                        { icon: "laptop", value: root.totals.hosts, label: qsTr("Hosts") },
                        { icon: "convo", value: root.totals.protocols, label: qsTr("Protocols") },
                        { icon: "ports", value: root.totals.services, label: qsTr("Services") },
                        { icon: "expert", value: root.totals.osTypes, label: qsTr("OS types") }
                    ]
                    ColumnLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: 2
                        Icon { Layout.alignment: Qt.AlignHCenter; name: modelData.icon; size: 20; color: Theme.accent }
                        Text { Layout.alignment: Qt.AlignHCenter; text: modelData.value !== undefined ? modelData.value : 0; color: Theme.text; font.pixelSize: 18; font.weight: Font.DemiBold }
                        Text { Layout.alignment: Qt.AlignHCenter; text: modelData.label; color: Theme.textMuted; font.pixelSize: 11 }
                    }
                }
            }

            Text { text: qsTr("Top protocols (by traffic)"); color: Theme.text; font.weight: Font.DemiBold; font.pixelSize: Theme.fontBody }
            Repeater {
                model: root.protocols
                RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    spacing: 8
                    readonly property color hue: modelData.name === qsTr("Other") ? Theme.textFaint : Theme.protocolColor(modelData.name)
                    Text { Layout.preferredWidth: 58; text: modelData.name; color: Theme.textMuted; font.pixelSize: Theme.fontSmall; elide: Text.ElideRight }
                    Rectangle {
                        Layout.fillWidth: true
                        implicitHeight: 8
                        radius: 4
                        color: Theme.border
                        Rectangle { width: parent.width * modelData.share; height: parent.height; radius: 4; color: parent.parent.hue }
                    }
                    Text {
                        Layout.preferredWidth: 44
                        horizontalAlignment: Text.AlignRight
                        text: (modelData.share * 100).toFixed(1) + "%"
                        color: Theme.textMuted
                        font.pixelSize: Theme.fontSmall
                    }
                }
            }

            Text { text: qsTr("Addressing"); color: Theme.text; font.weight: Font.DemiBold; font.pixelSize: Theme.fontBody }
            GridLayout {
                Layout.fillWidth: true
                columns: 2
                rowSpacing: 4
                Text { text: qsTr("Networks"); color: Theme.textMuted; font.pixelSize: Theme.fontSmall }
                Text { Layout.alignment: Qt.AlignRight; text: subnetModel.count; color: Theme.text; font.pixelSize: Theme.fontSmall }
                Text { text: qsTr("MAC vendors"); color: Theme.textMuted; font.pixelSize: Theme.fontSmall }
                Text { Layout.alignment: Qt.AlignRight; text: root.totals.vendors !== undefined ? root.totals.vendors : 0; color: Theme.text; font.pixelSize: Theme.fontSmall }
                Text { text: qsTr("Gateway vendor"); color: Theme.textMuted; font.pixelSize: Theme.fontSmall; visible: !!root.gateway.vendor }
                Text { Layout.alignment: Qt.AlignRight; Layout.maximumWidth: 170; elide: Text.ElideRight; visible: !!root.gateway.vendor
                       text: root.gateway.vendor || ""; color: Theme.text; font.pixelSize: Theme.fontSmall }
            }

            Item { Layout.fillHeight: true }
        }
    }
}
