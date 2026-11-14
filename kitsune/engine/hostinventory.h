/* hostinventory.h
 *
 * Kitsune - passive host discovery.
 *
 * HostInventory watches packets as the engine dissects them on its
 * first pass and builds a picture of the network: which hosts exist
 * (MAC, IPv4, IPv6, name), which services they offer, which operating
 * system they most likely run, and which subnet they belong to.
 *
 * Everything comes from traffic already captured; nothing is sent on
 * the network. Each operating system guess keeps the evidence behind
 * it so the interface can show learners why Kitsune thinks so.
 *
 * Engine thread only.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_HOSTINVENTORY_H
#define KITSUNE_HOSTINVENTORY_H

#include <QHash>
#include <QSet>
#include <QString>
#include <QVector>

#include "enginetypes.h"

typedef struct epan_dissect epan_dissect_t;
typedef struct _frame_data frame_data;
#include <stdint.h>

class HostInventory
{
public:
    HostInventory();

    /* Look up field ids. Call once, after epan_init. */
    void registerFields();

    /* Ask the engine to build the fields this class reads. Call before
     * each dissection. */
    void primeDissection(epan_dissect_t *edt) const;

    /* A look at a packet's raw headers before dissecting it. Most
     * packets only add to traffic counts, which the engine reports
     * without building a protocol tree; the few that can carry names,
     * banners or OS hints (handshakes, ARP, DHCP, DNS, NetBIOS, HTTP,
     * SSH, SMB) get a full tree. */
    struct Peek {
        bool needsTree = true;      /* when unsure, dissect fully */
        bool tcpParsed = false;     /* the TCP fields below are valid */
        int tcpPayload = -1;        /* bytes of TCP payload */
        int tcpFlags = 0;
        int ttl = -1;               /* IPv4 TTL or IPv6 hop limit */
        int window = -1;
        int mss = -1;
        int wscale = -1;
        bool timestamps = false;
    };
    static Peek peek(int encap, const uint8_t *data, unsigned length);

    /* Learn from one dissected packet. The tree may be absent, in
     * which case only addresses, ports and layers are used. */
    void addPacket(epan_dissect_t *edt, const frame_data *fdata, const Peek &peek);
    void addPacket(epan_dissect_t *edt, const frame_data *fdata);

    void clear();
    HostInventorySnapshot snapshot() const;

    /* Exposed for tests. */
    static QString subnetFor(const QString &ipv4);
    static bool isPrivateIpv4(const QString &ipv4);
    static QVector<OsEvidence> tcpEvidence(int ttl, int window, int mss, int wscale, bool timestamps, quint32 frame);
    static QVector<OsEvidence> userAgentEvidence(const QString &agent, quint32 frame);
    static QVector<OsEvidence> serverHeaderEvidence(const QString &server, quint32 frame);
    static QVector<OsEvidence> sshBannerEvidence(const QString &banner, quint32 frame);
    static QVector<OsEvidence> dhcpVendorEvidence(const QString &vendor, quint32 frame);
    static void chooseOs(HostRecord &host);

private:
    struct Fields {
        int eth_src = -1;
        int ip_src = -1, ip_dst = -1, ip_ttl = -1;
        int ipv6_src = -1, ipv6_dst = -1, ipv6_hlim = -1;
        int arp_opcode = -1, arp_src_mac = -1, arp_src_ip = -1;
        int tcp_srcport = -1, tcp_dstport = -1, tcp_flags = -1, tcp_window = -1, tcp_len = -1;
        int tcp_mss = -1, tcp_wscale = -1, tcp_option_kind = -1;
        int udp_srcport = -1, udp_dstport = -1;
        int http_server = -1, http_user_agent = -1;
        int ssh_protocol = -1;
        int dhcp_hostname = -1, dhcp_vendor = -1, dhcp_client_mac = -1, dhcp_router = -1;
        int dns_response = -1, dns_resp_name = -1, dns_a = -1;
        int nbns_name = -1;
        int smb_native_os = -1;
        int frame_protocols = -1;
    };

    int hostForIpv4(const QString &ip);
    int hostForIpv6(const QString &ip, const QString &mac);
    void addEvidence(int host, const QVector<OsEvidence> &evidence);
    ServiceRecord &serviceFor(int host, const QString &transport, quint16 port, quint32 frame);
    void setName(int host, const QString &name, const QString &source, int rank);

    Fields f_;
    QVector<HostRecord> hosts_;
    QVector<int> name_rank_;
    QHash<QString, int> by_ipv4_;
    QHash<QString, int> by_ipv6_;
    QHash<QString, QSet<QString>> mac_ipv4s_;   /* MAC -> IPv4s it sent from */
    QHash<QString, QString> ipv4_mac_;          /* IPv4 -> MAC it sent from (last seen) */
    QHash<QString, QString> arp_owner_;         /* MAC -> IPv4 that ARP says owns it */
    QSet<QString> dhcp_routers_;
    QSet<QString> evidence_seen_;               /* host|source|os, to count each kind once */

    /* Per-packet fast paths: integer keys, and memory of what each
     * host last sent, so repeat traffic skips the string work. */
    QHash<quint32, int> by_ipv4_num_;
    QHash<QString, quint32> mac_last_ip_;       /* MAC -> IPv4 it last sent from */
    QVector<int> last_layer_;                   /* per host: protocol id last recorded */
    QSet<quint64> syn_seen_;                    /* host + handshake fingerprint */
    QHash<QString, ProtocolShare> protocol_totals_;
};

#endif // KITSUNE_HOSTINVENTORY_H
