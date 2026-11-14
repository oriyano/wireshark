// NetworkView.qml
//
// Kitsune - what the capture reveals about the network: subnets, the
// hosts in each, and for one host its addresses, operating system
// (with the evidence behind the guess) and the services it offers.
// Everything is learned passively from the capture.
//
// SPDX-License-Identifier: GPL-2.0-or-later

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property string subnet: ""          // "" = all hosts
    property int hostRow: -1
    property var host: hostRow >= 0 ? subnetHostModel.host(hostRow) : ({})
    property int namesRevision: 0
    // The map first; choosing a network opens its host list.
    property bool showTopology: true

    // Host table columns; the optional ones drop out when space is short.
    readonly property int ipWidth: 120
    readonly property int osWidth: 210
    readonly property int servicesWidth: 170
    readonly property int trafficWidth: 70
    readonly property bool showServices: hostList.width > 720
    readonly property bool showTraffic: hostList.width > 820

    onSubnetChanged: { subnetHostModel.subnet = subnet; hostRow = -1 }
    onHostRowChanged: if (hostRow >= 0) showTopology = false
    Component.onCompleted: subnetHostModel.subnet = subnet

    Connections {
        target: kitsuneSettings
        function onSubnetNamesChanged() { root.namesRevision++ }
    }
    Connections {
        target: subnetHostModel
        function onCountChanged() {
            if (root.hostRow >= subnetHostModel.count) root.hostRow = -1
            root.host = root.hostRow >= 0 ? subnetHostModel.host(root.hostRow) : ({})
        }
    }

    function subnetLabel(cidr, suggested) {
        namesRevision   // re-evaluate when names change
        const custom = kitsuneSettings.subnetName(cidr)
        return custom.length > 0 ? custom : suggested
    }

    function osIcon(family, isRouter) {
        if (isRouter) return "router"
        if (family === "Embedded") return "chip"
        if (family === "Windows" || family === "macOS") return "laptop"
        if (family === "Linux") return "server"
        return "monitor"
    }

    function formatBytes(n) {
        if (n >= 1073741824) return (n / 1073741824).toFixed(1) + " GB"
        if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB"
        if (n >= 1024) return (n / 1024).toFixed(1) + " KB"
        return n + " B"
    }

    // Confidence: 0 unknown, 1 low, 2 medium, 3 high.
    component ConfidenceBadge: Rectangle {
        property int level: 0
        readonly property color hue: level === 3 ? Theme.success : level === 2 ? Theme.warning : Theme.textFaint
        visible: level > 0
        implicitWidth: confText.implicitWidth + 14
        implicitHeight: 20
        radius: 10
        color: Qt.rgba(hue.r, hue.g, hue.b, 0.14)
        border.color: Qt.rgba(hue.r, hue.g, hue.b, 0.4)
        Text {
            id: confText
            anchors.centerIn: parent
            text: parent.level === 3 ? qsTr("High") : parent.level === 2 ? qsTr("Medium") : qsTr("Low")
            color: parent.hue
            font.pixelSize: 11
            font.weight: Font.DemiBold
        }
    }

    component HeaderText: Text {
        color: Theme.textMuted
        font.pixelSize: Theme.fontSmall
        font.weight: Font.DemiBold
        elide: Text.ElideRight
    }

    component SectionTitle: Text {
        color: Theme.textMuted
        font.pixelSize: Theme.fontSmall
        font.weight: Font.DemiBold
        font.capitalization: Font.AllUppercase
        font.letterSpacing: 0.6
    }

    component Stat: ColumnLayout {
        property string label
        property string value
        spacing: 0
        Text { text: parent.value; color: Theme.text; font.pixelSize: 20; font.weight: Font.DemiBold }
        Text { text: parent.label; color: Theme.textMuted; font.pixelSize: Theme.fontSmall }
    }

    Text {
        visible: subnetModel.count === 0
        anchors.centerIn: parent
        text: captureEngine.loading ? qsTr("Building the host inventory…")
                                    : qsTr("No hosts found in this capture")
        color: Theme.textMuted
        font.pixelSize: Theme.fontLarge
    }

    // View switcher
    Rectangle {
        id: viewBar
        visible: subnetModel.count > 0
        anchors.left: parent.left
        anchors.right: parent.right
        height: 52
        color: Theme.surface
        Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Theme.border }
        Row {
            anchors.left: parent.left
            anchors.leftMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 4
            Repeater {
                model: [ { label: qsTr("Topology"), topology: true }, { label: qsTr("Networks and hosts"), topology: false } ]
                Rectangle {
                    required property var modelData
                    readonly property bool active: modelData.topology === root.showTopology
                    width: tabText.implicitWidth + 28
                    height: 32
                    radius: Theme.radiusSmall
                    color: active ? Theme.accentSoft : tabHover.hovered ? Theme.surfaceHover : "transparent"
                    border.color: active ? Theme.accent : "transparent"
                    Text {
                        id: tabText
                        anchors.centerIn: parent
                        text: parent.modelData.label
                        color: parent.active ? Theme.text : Theme.textMuted
                        font.pixelSize: Theme.fontBody
                        font.weight: parent.active ? Font.DemiBold : Font.Normal
                    }
                    HoverHandler { id: tabHover }
                    TapHandler { onTapped: root.showTopology = parent.modelData.topology }
                }
            }
        }
    }

    TopologyView {
        visible: subnetModel.count > 0 && root.showTopology
        anchors.top: viewBar.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        onSubnetChosen: (cidr) => { root.subnet = cidr; root.showTopology = false }
    }

    RowLayout {
        visible: subnetModel.count > 0 && !root.showTopology
        anchors.top: viewBar.bottom
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: 0

        // ---------------------------------------------------------- subnets
        Rectangle {
            Layout.preferredWidth: 260
            Layout.fillHeight: true
            color: Theme.surface

            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 12
                spacing: 8

                SectionTitle { text: qsTr("Networks"); Layout.leftMargin: 4 }

                // "All hosts" entry
                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: 48
                    radius: Theme.radiusSmall
                    color: root.subnet === "" ? Theme.selection : allHover.hovered ? Theme.surfaceHover : "transparent"
                    border.color: root.subnet === "" ? Theme.accent : "transparent"
                    HoverHandler { id: allHover }
                    TapHandler { onTapped: root.subnet = "" }
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 12
                        anchors.rightMargin: 12
                        Icon { name: "map"; size: 18; color: Theme.accent }
                        Text { Layout.fillWidth: true; text: qsTr("All hosts"); color: Theme.text; font.weight: Font.DemiBold; font.pixelSize: Theme.fontBody }
                        Text { text: hostModel.count; color: Theme.textMuted; font.pixelSize: Theme.fontBody }
                    }
                }

                ListView {
                    id: subnetList
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    spacing: 4
                    model: subnetModel
                    boundsBehavior: Flickable.StopAtBounds

                    delegate: Rectangle {
                        id: subnetItem
                        required property string cidr
                        required property string suggestedName
                        required property int hostCount
                        required property var osFamilies
                        readonly property bool selected: root.subnet === cidr
                        property bool editing: false

                        width: subnetList.width
                        implicitHeight: 64
                        radius: Theme.radiusSmall
                        color: selected ? Theme.selection : subnetHover.hovered ? Theme.surfaceHover : "transparent"
                        border.color: selected ? Theme.accent : "transparent"

                        HoverHandler { id: subnetHover }
                        TapHandler { onTapped: root.subnet = subnetItem.cidr }

                        RowLayout {
                            anchors.fill: parent
                            anchors.leftMargin: 12
                            anchors.rightMargin: 8
                            spacing: 10

                            Icon {
                                name: subnetItem.cidr === "Internet" ? "globe" : "map"
                                size: 18
                                color: subnetItem.selected ? Theme.accent : Theme.textMuted
                            }

                            ColumnLayout {
                                Layout.fillWidth: true
                                spacing: 2

                                Text {
                                    visible: !subnetItem.editing
                                    Layout.fillWidth: true
                                    text: root.subnetLabel(subnetItem.cidr, subnetItem.suggestedName) || subnetItem.cidr
                                    color: Theme.text
                                    font.pixelSize: Theme.fontBody
                                    font.weight: Font.DemiBold
                                    elide: Text.ElideRight
                                }
                                TextField {
                                    id: nameField
                                    visible: subnetItem.editing
                                    Layout.fillWidth: true
                                    implicitHeight: 24
                                    padding: 2
                                    text: root.subnetLabel(subnetItem.cidr, subnetItem.suggestedName)
                                    color: Theme.text
                                    font.pixelSize: Theme.fontBody
                                    background: Rectangle { radius: 4; color: Theme.surfaceRaised; border.color: Theme.accent }
                                    onAccepted: { kitsuneSettings.setSubnetName(subnetItem.cidr, text); subnetItem.editing = false }
                                    Keys.onEscapePressed: subnetItem.editing = false
                                    onActiveFocusChanged: if (!activeFocus) subnetItem.editing = false
                                }
                                Text {
                                    Layout.fillWidth: true
                                    text: subnetItem.cidr + "  ·  " + (subnetItem.hostCount === 1 ? qsTr("1 host") : qsTr("%1 hosts").arg(subnetItem.hostCount))
                                    color: Theme.textMuted
                                    font.family: Theme.monoFamily
                                    font.pixelSize: Theme.fontSmall
                                    elide: Text.ElideRight
                                }
                            }

                            // Rename
                            Rectangle {
                                visible: subnetHover.hovered && !subnetItem.editing && subnetItem.cidr !== "Internet"
                                implicitWidth: 26
                                implicitHeight: 26
                                radius: 13
                                color: editHover.hovered ? Theme.surfaceRaised : "transparent"
                                Icon { anchors.centerIn: parent; name: "edit"; size: 14; color: Theme.textMuted }
                                HoverHandler { id: editHover }
                                TapHandler {
                                    onTapped: {
                                        subnetItem.editing = true
                                        nameField.forceActiveFocus()
                                        nameField.selectAll()
                                    }
                                }
                                ToolTip.visible: editHover.hovered
                                ToolTip.text: qsTr("Rename this network")
                            }
                        }
                    }
                }
            }
        }

        Rectangle { Layout.fillHeight: true; implicitWidth: 1; color: Theme.border }

        // ---------------------------------------------------------- hosts
        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            clip: true
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                Layout.margins: 16
                spacing: 36
                ColumnLayout {
                    spacing: 2
                    Text {
                        text: root.subnet === "" ? qsTr("All hosts")
                              : (subnetModel.count >= 0 && root.subnetLabel(root.subnet, subnetModel.suggestedName(root.subnet)) || root.subnet)
                        color: Theme.text
                        font.pixelSize: Theme.fontTitle
                        font.weight: Font.DemiBold
                    }
                    Text {
                        visible: root.subnet !== ""
                        text: root.subnet
                        color: Theme.textMuted
                        font.family: Theme.monoFamily
                        font.pixelSize: Theme.fontSmall
                    }
                }
                Item { Layout.fillWidth: true }
                Stat { label: qsTr("Hosts"); value: subnetHostModel.count }
                Stat { label: qsTr("Open services"); value: subnetHostModel.totalServices }
                Stat { label: qsTr("OS types"); value: subnetHostModel.osTypes }
            }

            // Column headers
            Rectangle {
                Layout.fillWidth: true
                implicitHeight: 34
                color: Theme.surface
                Rectangle { anchors.top: parent.top; width: parent.width; height: 1; color: Theme.border }
                Rectangle { anchors.bottom: parent.bottom; width: parent.width; height: 1; color: Theme.border }
                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 16
                    anchors.rightMargin: 16
                    spacing: 12
                    HeaderText { Layout.fillWidth: true; Layout.minimumWidth: 140; text: qsTr("Host") }
                    HeaderText { Layout.preferredWidth: root.ipWidth; text: qsTr("IP address") }
                    HeaderText { Layout.preferredWidth: root.osWidth; text: qsTr("Operating system") }
                    HeaderText { visible: root.showServices; Layout.preferredWidth: root.servicesWidth; text: qsTr("Services") }
                    HeaderText { visible: root.showTraffic; Layout.preferredWidth: root.trafficWidth; text: qsTr("Traffic"); horizontalAlignment: Text.AlignRight }
                }
            }

            ListView {
                id: hostList
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                model: subnetHostModel
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar {
                    policy: ScrollBar.AsNeeded
                    contentItem: Rectangle { implicitWidth: 8; radius: 4; color: Theme.borderStrong }
                }

                delegate: Rectangle {
                    id: hostItem
                    required property int index
                    required property string name
                    required property string ipv4
                    required property string mac
                    required property string vendor
                    required property string os
                    required property string osFamily
                    required property int osConfidence
                    required property string services
                    required property bool isRouter
                    required property var bytes
                    readonly property bool selected: index === root.hostRow

                    width: hostList.width
                    implicitHeight: 52
                    color: selected ? Theme.selection : rowHover.hovered ? Theme.surfaceHover
                         : (index % 2 ? Theme.rowAlt : Theme.surface)
                    HoverHandler { id: rowHover }
                    TapHandler { onTapped: root.hostRow = hostItem.index }
                    Rectangle { visible: hostItem.selected; width: 3; height: parent.height; color: Theme.accent }

                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 16
                        anchors.rightMargin: 16
                        spacing: 12

                        RowLayout {
                            Layout.fillWidth: true
                            Layout.minimumWidth: 140
                            Layout.preferredWidth: 140
                            spacing: 10
                            Rectangle {
                                implicitWidth: 32; implicitHeight: 32; radius: 8
                                color: hostItem.isRouter ? Theme.accentSoft : Theme.surfaceRaised
                                border.color: Theme.border
                                Icon { anchors.centerIn: parent; name: root.osIcon(hostItem.osFamily, hostItem.isRouter); size: 18
                                       color: hostItem.isRouter ? Theme.accent : Theme.textMuted }
                            }
                            ColumnLayout {
                                Layout.fillWidth: true
                                Layout.preferredWidth: 0
                                spacing: 1
                                Text { Layout.fillWidth: true; text: hostItem.name; color: Theme.text; font.pixelSize: Theme.fontBody; font.weight: Font.DemiBold; elide: Text.ElideRight }
                                Text { Layout.fillWidth: true; text: hostItem.vendor.length > 0 ? hostItem.vendor : hostItem.mac; color: Theme.textFaint; font.pixelSize: Theme.fontSmall; elide: Text.ElideRight }
                            }
                        }
                        Text {
                            Layout.preferredWidth: root.ipWidth
                            text: hostItem.ipv4
                            color: Theme.textMuted
                            font.family: Theme.monoFamily
                            font.pixelSize: Theme.fontBody
                            elide: Text.ElideRight
                        }
                        RowLayout {
                            Layout.preferredWidth: root.osWidth
                            Layout.maximumWidth: root.osWidth
                            spacing: 8
                            Text {
                                Layout.fillWidth: true
                                text: hostItem.os.length > 0 ? hostItem.os : qsTr("Unknown")
                                color: hostItem.os.length > 0 ? Theme.text : Theme.textFaint
                                font.pixelSize: Theme.fontBody
                                elide: Text.ElideRight
                            }
                            ConfidenceBadge { level: hostItem.osConfidence }
                        }
                        Text {
                            visible: root.showServices
                            Layout.preferredWidth: root.servicesWidth
                            text: hostItem.services.length > 0 ? hostItem.services : "—"
                            color: hostItem.services.length > 0 ? Theme.text : Theme.textFaint
                            font.pixelSize: Theme.fontBody
                            elide: Text.ElideRight
                        }
                        Text {
                            visible: root.showTraffic
                            Layout.preferredWidth: root.trafficWidth
                            text: root.formatBytes(hostItem.bytes)
                            color: Theme.textMuted
                            font.pixelSize: Theme.fontBody
                            horizontalAlignment: Text.AlignRight
                        }
                    }
                }
            }
        }

        Rectangle { visible: root.hostRow >= 0; Layout.fillHeight: true; implicitWidth: 1; color: Theme.border }

        // ---------------------------------------------------------- host panel
        Flickable {
            visible: root.hostRow >= 0
            Layout.preferredWidth: 340
            Layout.fillHeight: true
            clip: true
            contentHeight: panel.implicitHeight + 32
            boundsBehavior: Flickable.StopAtBounds
            ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

            ColumnLayout {
                id: panel
                x: 16
                y: 16
                width: parent.width - 32
                spacing: 14

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 12
                    Rectangle {
                        implicitWidth: 44; implicitHeight: 44; radius: 10
                        color: Theme.accentSoft
                        Icon { anchors.centerIn: parent; name: root.osIcon(root.host.osFamily || "", root.host.isRouter || false); size: 24; color: Theme.accent }
                    }
                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 2
                        Text { Layout.fillWidth: true; text: root.host.name || ""; color: Theme.text; font.pixelSize: 18; font.weight: Font.DemiBold; elide: Text.ElideRight }
                        Text {
                            Layout.fillWidth: true
                            text: root.host.isRouter ? qsTr("Router / gateway") : (root.host.nameSource ? qsTr("Name from %1").arg(root.host.nameSource) : qsTr("No name seen"))
                            color: Theme.textMuted; font.pixelSize: Theme.fontSmall
                        }
                    }
                    ToolButton {
                        implicitWidth: 28; implicitHeight: 28
                        onClicked: root.hostRow = -1
                        background: Rectangle { radius: 14; color: parent.hovered ? Theme.surfaceHover : "transparent" }
                        contentItem: Item { Icon { anchors.centerIn: parent; name: "close"; size: 14; color: Theme.textMuted } }
                    }
                }

                // Addresses
                SectionTitle { text: qsTr("Addresses") }
                GridLayout {
                    Layout.fillWidth: true
                    columns: 2
                    columnSpacing: 14
                    rowSpacing: 6
                    Repeater {
                        model: [
                            { k: qsTr("IPv4"), v: root.host.ipv4 || "" },
                            { k: qsTr("IPv6"), v: (root.host.ipv6 || []).join("\n") },
                            { k: qsTr("MAC"), v: root.host.mac || "" },
                            { k: qsTr("Vendor"), v: root.host.vendor || "" },
                            { k: qsTr("Network"), v: root.host.subnet || "" }
                        ].filter(function(e) { return e.v.length > 0 })
                        delegate: Item {
                            required property var modelData
                            Layout.columnSpan: 2
                            Layout.fillWidth: true
                            implicitHeight: Math.max(kText.implicitHeight, vText.implicitHeight)
                            Text { id: kText; width: 70; text: parent.modelData.k; color: Theme.textMuted; font.pixelSize: Theme.fontBody }
                            Text {
                                id: vText
                                x: 80; width: parent.width - 80
                                text: parent.modelData.v
                                color: Theme.text
                                font.family: Theme.monoFamily
                                font.pixelSize: Theme.fontBody
                                wrapMode: Text.WrapAnywhere
                            }
                        }
                    }
                }

                // Operating system
                SectionTitle { text: qsTr("Operating system") }
                Rectangle {
                    Layout.fillWidth: true
                    implicitHeight: osColumn.implicitHeight + 24
                    radius: Theme.radiusSmall
                    color: Theme.surfaceRaised
                    border.color: Theme.border
                    ColumnLayout {
                        id: osColumn
                        x: 12; y: 12
                        width: parent.width - 24
                        spacing: 8
                        RowLayout {
                            Layout.fillWidth: true
                            Text {
                                Layout.fillWidth: true
                                text: root.host.os || qsTr("Not enough evidence yet")
                                color: root.host.os ? Theme.text : Theme.textFaint
                                font.pixelSize: Theme.fontLarge
                                font.weight: Font.DemiBold
                                wrapMode: Text.WordWrap
                            }
                            ConfidenceBadge { level: root.host.osConfidence || 0 }
                        }
                        Text {
                            visible: (root.host.osEvidence || []).length > 0
                            text: qsTr("Why Kitsune thinks so:")
                            color: Theme.textMuted
                            font.pixelSize: Theme.fontSmall
                        }
                        Repeater {
                            model: root.host.osEvidence || []
                            delegate: ColumnLayout {
                                required property var modelData
                                Layout.fillWidth: true
                                spacing: 1
                                RowLayout {
                                    Layout.fillWidth: true
                                    Rectangle { implicitWidth: 6; implicitHeight: 6; radius: 3; color: Theme.accent }
                                    Text {
                                        Layout.fillWidth: true
                                        text: modelData.source + " → " + modelData.os
                                        color: Theme.text
                                        font.pixelSize: Theme.fontSmall
                                        elide: Text.ElideRight
                                    }
                                    Text { text: qsTr("#%1").arg(modelData.frame); color: Theme.textFaint; font.pixelSize: 11 }
                                }
                                Text {
                                    Layout.fillWidth: true
                                    Layout.leftMargin: 14
                                    text: modelData.detail
                                    color: Theme.textMuted
                                    font.family: Theme.monoFamily
                                    font.pixelSize: 11
                                    elide: Text.ElideRight
                                }
                            }
                        }
                    }
                }

                // Services
                SectionTitle { text: qsTr("Services (%1)").arg((root.host.services || []).length) }
                Text {
                    visible: (root.host.services || []).length === 0
                    text: qsTr("No listening services seen")
                    color: Theme.textFaint
                    font.pixelSize: Theme.fontBody
                }
                Repeater {
                    model: root.host.services || []
                    delegate: Rectangle {
                        required property var modelData
                        Layout.fillWidth: true
                        implicitHeight: svcColumn.implicitHeight + 16
                        radius: Theme.radiusSmall
                        color: Theme.surfaceRaised
                        border.color: Theme.border
                        ColumnLayout {
                            id: svcColumn
                            x: 12; y: 8
                            width: parent.width - 24
                            spacing: 2
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 8
                                Rectangle {
                                    implicitWidth: portText.implicitWidth + 12
                                    implicitHeight: 20
                                    radius: 4
                                    color: Theme.accentSoft
                                    Text {
                                        id: portText
                                        anchors.centerIn: parent
                                        text: modelData.port + "/" + modelData.transport
                                        color: Theme.accent
                                        font.family: Theme.monoFamily
                                        font.pixelSize: 11
                                        font.weight: Font.DemiBold
                                    }
                                }
                                Text {
                                    Layout.fillWidth: true
                                    text: modelData.service || qsTr("unknown service")
                                    color: Theme.text
                                    font.pixelSize: Theme.fontBody
                                    font.weight: Font.DemiBold
                                }
                                Text {
                                    text: qsTr("%1 pkts").arg(modelData.packets)
                                    color: Theme.textFaint
                                    font.pixelSize: 11
                                }
                            }
                            Text {
                                visible: (modelData.banner || "").length > 0
                                Layout.fillWidth: true
                                text: modelData.banner || ""
                                color: Theme.textMuted
                                font.family: Theme.monoFamily
                                font.pixelSize: 11
                                elide: Text.ElideRight
                            }
                        }
                        TapHandler {
                            onTapped: {
                                const ip = root.host.ipv4
                                if (ip) {
                                    window.currentView = "packets"
                                    captureEngine.applyFilter("ip.addr == " + ip + " && " + modelData.transport.toLowerCase() + ".port == " + modelData.port)
                                }
                            }
                        }
                    }
                }

                // Protocols
                SectionTitle { visible: (root.host.protocols || []).length > 0; text: qsTr("Protocols seen") }
                Flow {
                    Layout.fillWidth: true
                    spacing: 6
                    Repeater {
                        model: root.host.protocols || []
                        delegate: Rectangle {
                            required property string modelData
                            readonly property color hue: Theme.protocolColor(modelData)
                            width: pText.implicitWidth + 14
                            height: 22
                            radius: 11
                            color: Qt.rgba(hue.r, hue.g, hue.b, 0.14)
                            Text { id: pText; anchors.centerIn: parent; text: parent.modelData.toUpperCase(); color: parent.hue; font.pixelSize: 11; font.weight: Font.DemiBold }
                        }
                    }
                }

                // Traffic
                SectionTitle { text: qsTr("Traffic") }
                Text {
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                    text: qsTr("Sent %1 packets (%2), received %3 packets (%4). First seen in packet %5, last in %6.")
                          .arg(root.host.packetsSent || 0).arg(root.formatBytes(root.host.bytesSent || 0))
                          .arg(root.host.packetsReceived || 0).arg(root.formatBytes(root.host.bytesReceived || 0))
                          .arg(root.host.firstFrame || 0).arg(root.host.lastFrame || 0)
                    color: Theme.textMuted
                    font.pixelSize: Theme.fontBody
                }
                Button {
                    Layout.fillWidth: true
                    implicitHeight: 36
                    enabled: (root.host.ipv4 || "").length > 0
                    onClicked: {
                        window.currentView = "packets"
                        captureEngine.applyFilter((root.host.ipv4.indexOf(":") >= 0 ? "ipv6.addr == " : "ip.addr == ") + root.host.ipv4)
                    }
                    background: Rectangle { radius: Theme.radiusSmall; color: parent.hovered ? Theme.accentStrong : Theme.accent }
                    contentItem: Text {
                        text: qsTr("Show this host's packets")
                        color: Theme.onAccent
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        font.weight: Font.DemiBold
                        font.pixelSize: Theme.fontBody
                    }
                }
            }
        }
    }
}
