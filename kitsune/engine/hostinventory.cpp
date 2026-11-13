/* hostinventory.cpp
 *
 * Kitsune - passive host discovery.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "hostinventory.h"

#include <cstdio>

#include <QMap>
#include <QRegularExpression>

#include <glib.h>

#include <epan/addr_resolv.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data.h>
#include <epan/proto.h>
#include <cstring>
#include <wiretap/wtap.h>
#include <epan/packet_info.h>
#include <epan/to_str.h>
#include <epan/address.h>
#include <epan/ftypes/ftypes.h>

/* A MAC sending from more IPv4 addresses than this is treated as a
 * router forwarding other hosts' traffic, not as one host. */
static const int router_ip_threshold = 3;

/* Name sources, best first. */
enum { RankNone = 0, RankDns = 1, RankNbns = 2, RankDhcp = 3 };

HostInventory::HostInventory() = default;

static int fieldId(const char *name)
{
    return proto_registrar_get_id_byname(name);
}

void HostInventory::registerFields()
{
    f_.eth_src = fieldId("eth.src");
    f_.ip_src = fieldId("ip.src");
    f_.ip_dst = fieldId("ip.dst");
    f_.ip_ttl = fieldId("ip.ttl");
    f_.ipv6_src = fieldId("ipv6.src");
    f_.ipv6_dst = fieldId("ipv6.dst");
    f_.ipv6_hlim = fieldId("ipv6.hlim");
    f_.arp_opcode = fieldId("arp.opcode");
    f_.arp_src_mac = fieldId("arp.src.hw_mac");
    f_.arp_src_ip = fieldId("arp.src.proto_ipv4");
    f_.tcp_srcport = fieldId("tcp.srcport");
    f_.tcp_dstport = fieldId("tcp.dstport");
    f_.tcp_flags = fieldId("tcp.flags");
    f_.tcp_window = fieldId("tcp.window_size_value");
    f_.tcp_len = fieldId("tcp.len");
    f_.tcp_mss = fieldId("tcp.options.mss_val");
    f_.tcp_wscale = fieldId("tcp.options.wscale.shift");
    f_.tcp_option_kind = fieldId("tcp.option_kind");
    f_.udp_srcport = fieldId("udp.srcport");
    f_.udp_dstport = fieldId("udp.dstport");
    f_.http_server = fieldId("http.server");
    f_.http_user_agent = fieldId("http.user_agent");
    f_.ssh_protocol = fieldId("ssh.protocol");
    f_.dhcp_hostname = fieldId("dhcp.option.hostname");
    f_.dhcp_vendor = fieldId("dhcp.option.vendor_class_id");
    f_.dhcp_client_mac = fieldId("dhcp.hw.mac_addr");
    f_.dhcp_router = fieldId("dhcp.option.router");
    f_.dns_response = fieldId("dns.flags.response");
    f_.dns_resp_name = fieldId("dns.resp.name");
    f_.dns_a = fieldId("dns.a");
    f_.nbns_name = fieldId("nbns.name");
    f_.smb_native_os = fieldId("smb.native_os");
}

void HostInventory::primeDissection(epan_dissect_t *edt) const
{
    const int *ids = &f_.eth_src;
    const int count = static_cast<int>(sizeof(Fields) / sizeof(int));
    for (int i = 0; i < count; i++) {
        if (ids[i] > 0) {
            epan_dissect_prime_with_hfid(edt, ids[i]);
        }
    }
}

void HostInventory::clear()
{
    hosts_.clear();
    name_rank_.clear();
    by_ipv4_.clear();
    by_ipv4_num_.clear();
    mac_last_ip_.clear();
    last_layer_.clear();
    syn_seen_.clear();
    by_ipv6_.clear();
    mac_ipv4s_.clear();
    ipv4_mac_.clear();
    arp_owner_.clear();
    dhcp_routers_.clear();
    evidence_seen_.clear();
}

/* Field access. This runs for every packet of the first pass, so the
 * common types skip the engine's generic string conversion, and
 * addresses are formatted once and then looked up. */
static QString ipv4Text(quint32 addr)
{
    static QHash<quint32, QString> cache;
    auto it = cache.constFind(addr);
    if (it != cache.constEnd()) {
        return it.value();
    }
    if (cache.size() > 200000) {
        cache.clear();
    }
    const QString text = QStringLiteral("%1.%2.%3.%4").arg(addr >> 24).arg((addr >> 16) & 0xff)
                                                      .arg((addr >> 8) & 0xff).arg(addr & 0xff);
    cache.insert(addr, text);
    return text;
}

static QString etherText(const uint8_t *b)
{
    static QHash<quint64, QString> cache;
    quint64 key = 0;
    for (int i = 0; i < 6; i++) {
        key = (key << 8) | b[i];
    }
    auto it = cache.constFind(key);
    if (it != cache.constEnd()) {
        return it.value();
    }
    if (cache.size() > 200000) {
        cache.clear();
    }
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    const QString text = QString::fromLatin1(buf);
    cache.insert(key, text);
    return text;
}

static QString fieldText(field_info *fi)
{
    fvalue_t *fv = fi->value;
    switch (fvalue_type_ftenum(fv)) {
    case FT_IPv4:
        return ipv4Text(fvalue_get_ipv4(fv)->addr);
    case FT_ETHER:
        return etherText(static_cast<const uint8_t *>(fvalue_get_bytes_data(fv)));
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        return QString::fromUtf8(fvalue_get_string(fv));
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        /* Hex-displayed integers keep their engine format below. */
        if (FIELD_DISPLAY(fi->hfinfo->display) == BASE_DEC || FIELD_DISPLAY(fi->hfinfo->display) == BASE_NONE) {
            return QString::number(fvalue_get_uinteger(fv));
        }
        break;
    default:
        break;
    }
    char *repr = fvalue_to_string_repr(NULL, fv, FTREPR_DISPLAY, fi->hfinfo->display);
    QString out = repr ? QString::fromUtf8(repr) : QString();
    g_free(repr);
    return out;
}

static field_info *firstField(epan_dissect_t *edt, int hfid)
{
    if (hfid <= 0 || !edt->tree) {
        return nullptr;
    }
    GPtrArray *finfos = proto_get_finfo_ptr_array(edt->tree, hfid);
    if (!finfos) {
        return nullptr;
    }
    for (unsigned i = 0; i < finfos->len; i++) {
        field_info *fi = static_cast<field_info *>(g_ptr_array_index(finfos, i));
        if (fi && fi->value) {
            return fi;
        }
    }
    return nullptr;
}

/* All values of a field in this packet, as display strings. */
static QStringList values(epan_dissect_t *edt, int hfid)
{
    QStringList out;
    if (hfid <= 0 || !edt->tree) {
        return out;
    }
    GPtrArray *finfos = proto_get_finfo_ptr_array(edt->tree, hfid);
    if (!finfos) {
        return out;
    }
    for (unsigned i = 0; i < finfos->len; i++) {
        field_info *fi = static_cast<field_info *>(g_ptr_array_index(finfos, i));
        if (fi && fi->value) {
            out << fieldText(fi);
        }
    }
    return out;
}

static QString first(epan_dissect_t *edt, int hfid)
{
    field_info *fi = firstField(edt, hfid);
    return fi ? fieldText(fi) : QString();
}

static int firstInt(epan_dissect_t *edt, int hfid, int fallback = -1)
{
    field_info *fi = firstField(edt, hfid);
    if (!fi) {
        return fallback;
    }
    switch (fvalue_type_ftenum(fi->value)) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    case FT_FRAMENUM:
        return static_cast<int>(fvalue_get_uinteger(fi->value));
    case FT_INT8:
    case FT_INT16:
    case FT_INT24:
    case FT_INT32:
        return static_cast<int>(fvalue_get_sinteger(fi->value));
    case FT_BOOLEAN:
        return fvalue_get_uinteger64(fi->value) ? 1 : 0;
    default:
        break;
    }
    bool ok = false;
    const int value = fieldText(fi).toInt(&ok, 0);
    return ok ? value : fallback;
}

static QString macVendor(const QString &mac)
{
    const QStringList parts = mac.split(QLatin1Char(':'));
    if (parts.size() < 3) {
        return QString();
    }
    uint8_t oui[3];
    for (int i = 0; i < 3; i++) {
        oui[i] = static_cast<uint8_t>(parts[i].toUInt(nullptr, 16));
    }
    const char *name = get_manuf_name_if_known(oui, sizeof(oui));
    return name ? QString::fromUtf8(name) : QString();
}

bool HostInventory::isPrivateIpv4(const QString &ipv4)
{
    const QStringList o = ipv4.split(QLatin1Char('.'));
    if (o.size() != 4) {
        return false;
    }
    const int a = o[0].toInt(), b = o[1].toInt();
    return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
           (a == 169 && b == 254) || a == 127;
}

QString HostInventory::subnetFor(const QString &ipv4)
{
    const QStringList o = ipv4.split(QLatin1Char('.'));
    if (o.size() != 4) {
        return QString();
    }
    if (!isPrivateIpv4(ipv4)) {
        return QStringLiteral("Internet");
    }
    return QStringLiteral("%1.%2.%3.0/24").arg(o[0], o[1], o[2]);
}

int HostInventory::hostForIpv4(const QString &ip)
{
    auto it = by_ipv4_.constFind(ip);
    if (it != by_ipv4_.constEnd()) {
        return it.value();
    }
    HostRecord host;
    host.ipv4 = ip;
    host.subnet = subnetFor(ip);
    hosts_.append(host);
    name_rank_.append(RankNone);
    last_layer_.append(-1);
    const int index = static_cast<int>(hosts_.size()) - 1;
    by_ipv4_.insert(ip, index);
    return index;
}

int HostInventory::hostForIpv6(const QString &ip, const QString &mac)
{
    auto it = by_ipv6_.constFind(ip);
    if (it != by_ipv6_.constEnd()) {
        return it.value();
    }
    /* Join an IPv4 host that uses the same MAC, when there is one. */
    int index = -1;
    if (!mac.isEmpty()) {
        for (auto v4 = ipv4_mac_.constBegin(); v4 != ipv4_mac_.constEnd(); ++v4) {
            if (v4.value() == mac && mac_ipv4s_.value(mac).size() <= router_ip_threshold) {
                index = by_ipv4_.value(v4.key(), -1);
                break;
            }
        }
    }
    if (index < 0) {
        HostRecord host;
        host.subnet = ip.startsWith(QLatin1String("fe80")) ? QStringLiteral("fe80::/64 (link-local)")
                                                          : ip.section(QLatin1Char(':'), 0, 3) + QStringLiteral("::/64");
        hosts_.append(host);
        name_rank_.append(RankNone);
        last_layer_.append(-1);
        index = static_cast<int>(hosts_.size()) - 1;
    }
    if (!hosts_[index].ipv6.contains(ip)) {
        hosts_[index].ipv6 << ip;
    }
    by_ipv6_.insert(ip, index);
    return index;
}

void HostInventory::setName(int host, const QString &name, const QString &source, int rank)
{
    if (host < 0 || name.isEmpty() || rank < name_rank_[host]) {
        return;
    }
    hosts_[host].name = name;
    hosts_[host].nameSource = source;
    name_rank_[host] = rank;
}

void HostInventory::addEvidence(int host, const QVector<OsEvidence> &evidence)
{
    for (const OsEvidence &e : evidence) {
        const QString key = QStringLiteral("%1|%2|%3").arg(host).arg(e.source, e.os);
        if (evidence_seen_.contains(key)) {
            continue;
        }
        evidence_seen_.insert(key);
        hosts_[host].osEvidence.append(e);
    }
}

ServiceRecord &HostInventory::serviceFor(int host, const QString &transport, quint16 port, quint32 frame)
{
    QVector<ServiceRecord> &services = hosts_[host].services;
    for (ServiceRecord &s : services) {
        if (s.port == port && s.transport == transport) {
            return s;
        }
    }
    ServiceRecord record;
    record.transport = transport;
    record.port = port;
    record.firstFrame = frame;
    services.append(record);
    return services.last();
}

static bool isTransportOrBelow(const QString &proto)
{
    static const QSet<QString> lower = {
        QStringLiteral("eth"), QStringLiteral("ethertype"), QStringLiteral("ip"), QStringLiteral("ipv6"),
        QStringLiteral("tcp"), QStringLiteral("udp"), QStringLiteral("arp"), QStringLiteral("icmp"),
        QStringLiteral("icmpv6"), QStringLiteral("vlan"), QStringLiteral("frame"), QStringLiteral("sll")
    };
    return lower.contains(proto);
}


static inline unsigned be16(const uint8_t *p) { return (static_cast<unsigned>(p[0]) << 8) | p[1]; }

/* TCP ports whose every packet may matter (SMB carries the OS name
 * mid-stream). HTTP and SSH are found by their payload instead. */
static bool interestingTcpPort(unsigned port)
{
    return port == 139 || port == 445;
}

static bool interestingUdpPort(unsigned port)
{
    switch (port) {
    case 67: case 68: case 137: case 138:
        return true;
    default:
        return false;
    }
}

/* Payloads that start like HTTP or SSH, on any port. */
static bool interestingPayload(const uint8_t *p, unsigned len)
{
    if (len < 4) return false;
    return !memcmp(p, "GET ", 4) || !memcmp(p, "POST", 4) || !memcmp(p, "HEAD", 4) ||
           !memcmp(p, "PUT ", 4) || !memcmp(p, "HTTP", 4) || !memcmp(p, "SSH-", 4);
}

HostInventory::Peek HostInventory::peek(int encap, const uint8_t *data, unsigned length)
{
    Peek result;
    if (encap != WTAP_ENCAP_ETHERNET || !data || length < 14) {
        return result;
    }
    unsigned offset = 12;
    unsigned ethertype = be16(data + offset);
    while ((ethertype == 0x8100 || ethertype == 0x88a8) && length >= offset + 6) {
        offset += 4;
        ethertype = be16(data + offset);
    }
    offset += 2;

    unsigned proto = 0, l4 = 0, l3_end = 0;
    int ttl = -1;
    if (ethertype == 0x0800) {
        if (length < offset + 20 || (data[offset] >> 4) != 4) return result;
        const unsigned ihl = (data[offset] & 0x0f) * 4u;
        const unsigned total = be16(data + offset + 2);
        const unsigned frag = be16(data + offset + 6) & 0x1fff;
        if (ihl < 20 || frag != 0) return result;
        proto = data[offset + 9];
        ttl = data[offset + 8];
        l4 = offset + ihl;
        l3_end = qMin(length, offset + total);
    } else if (ethertype == 0x86dd) {
        if (length < offset + 40) return result;
        proto = data[offset + 6];   /* extension headers: dissect fully */
        ttl = data[offset + 7];
        l4 = offset + 40;
        l3_end = qMin(length, offset + 40 + be16(data + offset + 4));
    } else {
        return result;              /* ARP and everything else */
    }

    if (proto == 6) {
        if (l3_end < l4 + 20) return result;
        const unsigned sport = be16(data + l4), dport = be16(data + l4 + 2);
        const unsigned hlen = (data[l4 + 12] >> 4) * 4u;
        const unsigned flags = data[l4 + 13];
        if (hlen < 20 || l3_end < l4 + hlen) return result;
        result.tcpParsed = true;
        result.tcpPayload = static_cast<int>(l3_end - l4 - hlen);
        result.tcpFlags = static_cast<int>(flags);
        result.ttl = ttl;
        result.window = static_cast<int>(be16(data + l4 + 14));
        /* Handshake options, which hint at the operating system. */
        for (unsigned o = l4 + 20; o < l4 + hlen;) {
            const uint8_t kind = data[o];
            if (kind == 0) break;
            if (kind == 1) { o++; continue; }
            if (o + 1 >= l4 + hlen) break;
            const unsigned len = data[o + 1];
            if (len < 2 || o + len > l4 + hlen) break;
            if (kind == 2 && len == 4) result.mss = static_cast<int>(be16(data + o + 2));
            else if (kind == 3 && len == 3) result.wscale = data[o + 2];
            else if (kind == 8) result.timestamps = true;
            o += len;
        }
        result.needsTree = interestingTcpPort(sport) || interestingTcpPort(dport) ||
                           interestingPayload(data + l4 + hlen, l3_end - l4 - hlen);
        return result;
    }
    if (proto == 17) {
        if (l3_end < l4 + 8) return result;
        const unsigned sport = be16(data + l4), dport = be16(data + l4 + 2);
        if (sport == 53 || sport == 5353 || dport == 5353) {
            /* DNS: only responses name hosts. */
            result.needsTree = l3_end < l4 + 11 || (data[l4 + 10] & 0x80);
            return result;
        }
        result.needsTree = interestingUdpPort(sport) || interestingUdpPort(dport);
        return result;
    }
    if (proto == 1 || proto == 58) {
        result.needsTree = false;   /* ICMP adds nothing but counts */
    }
    return result;
}

static QString addressText(const address &addr)
{
    if (addr.type == AT_IPv4 && addr.len == 4) {
        uint32_t v;
        memcpy(&v, addr.data, 4);
        return ipv4Text(g_ntohl(v));
    }
    if (addr.type == AT_ETHER && addr.len == 6) {
        return etherText(static_cast<const uint8_t *>(addr.data));
    }
    if (addr.type == AT_IPv6) {
        char *text = address_to_str(NULL, &addr);
        QString out = QString::fromUtf8(text);
        wmem_free(NULL, text);
        return out;
    }
    return QString();
}

/* The highest-level protocol the engine found, e.g. "http" for
 * eth:ethertype:ip:tcp:http:json, with what the inventory needs to
 * know about it worked out once per protocol. */
struct LayerInfo {
    int id = -1;
    QString upper;          /* "HTTP" */
    bool lower = false;     /* transport or below: not a service name */
};

static const LayerInfo *topLayer(packet_info *pinfo)
{
    static const QSet<QString> skip = {
        QStringLiteral("data"), QStringLiteral("json"), QStringLiteral("xml"),
        QStringLiteral("media"), QStringLiteral("image-gif"), QStringLiteral("png")
    };
    static QHash<int, LayerInfo *> infos;
    static LayerInfo none;
    if (!pinfo->layers) {
        return &none;
    }
    const LayerInfo *top = &none;
    for (wmem_list_frame_t *f = wmem_list_head(pinfo->layers); f; f = wmem_list_frame_next(f)) {
        const int proto_id = GPOINTER_TO_INT(wmem_list_frame_data(f));
        LayerInfo *info = infos.value(proto_id);
        if (!info) {
            const QString name = QString::fromUtf8(proto_get_protocol_filter_name(proto_id));
            info = new LayerInfo;   /* one per protocol, kept for the process */
            info->id = skip.contains(name) ? -1 : proto_id;
            info->upper = name.toUpper();
            info->lower = isTransportOrBelow(name);
            infos.insert(proto_id, info);
        }
        if (info->id >= 0) {
            top = info;
        }
    }
    return top;
}

void HostInventory::addPacket(epan_dissect_t *edt, const frame_data *fdata)
{
    addPacket(edt, fdata, Peek());
}

void HostInventory::addPacket(epan_dissect_t *edt, const frame_data *fdata, const Peek &peek)
{
    const quint32 frame = fdata->num;
    const quint64 length = fdata->pkt_len;
    packet_info *pinfo = &edt->pi;
    const LayerInfo *layer = topLayer(pinfo);
    const QString &top_upper = layer->upper;
    const bool top_is_lower = layer->id < 0 || layer->lower;
    const QString mac = addressText(pinfo->dl_src);

    /* ARP tells us which IPv4 address owns a MAC. */
    const QString arp_ip = first(edt, f_.arp_src_ip);
    if (!arp_ip.isEmpty()) {
        const QString arp_mac = first(edt, f_.arp_src_mac);
        const int host = hostForIpv4(arp_ip);
        if (!arp_mac.isEmpty()) {
            arp_owner_.insert(arp_mac, arp_ip);
            mac_ipv4s_[arp_mac].insert(arp_ip);
            ipv4_mac_.insert(arp_ip, arp_mac);
        }
        hosts_[host].packetsSent++;
        hosts_[host].bytesSent += length;
        if (!hosts_[host].protocols.contains(QLatin1String("ARP"))) {
            hosts_[host].protocols << QStringLiteral("ARP");
        }
        if (hosts_[host].firstFrame == 0) hosts_[host].firstFrame = frame;
        hosts_[host].lastFrame = frame;
        return;
    }

    int src = -1, dst = -1;
    int ttl = -1;
    const bool v4 = pinfo->net_src.type == AT_IPv4 && pinfo->net_src.len == 4;
    QString ip_src;
    if (v4) {
        uint32_t raw;
        memcpy(&raw, pinfo->net_src.data, 4);
        const quint32 src_num = g_ntohl(raw);
        src = by_ipv4_num_.value(src_num, -1);
        if (src < 0) {
            src = hostForIpv4(ipv4Text(src_num));
            by_ipv4_num_.insert(src_num, src);
        }
        ip_src = hosts_[src].ipv4;
        if (pinfo->net_dst.type == AT_IPv4 && pinfo->net_dst.len == 4) {
            memcpy(&raw, pinfo->net_dst.data, 4);
            const quint32 dst_num = g_ntohl(raw);
            /* Broadcast and multicast destinations are not hosts. */
            if ((dst_num >> 24) < 224 && (dst_num & 0xff) != 0xff) {
                dst = by_ipv4_num_.value(dst_num, -1);
                if (dst < 0) {
                    dst = hostForIpv4(ipv4Text(dst_num));
                    by_ipv4_num_.insert(dst_num, dst);
                }
            }
        }
        ttl = firstInt(edt, f_.ip_ttl);
        if (!mac.isEmpty() && src_num != 0) {    /* 0.0.0.0: a DHCP client with no address yet */
            auto last = mac_last_ip_.find(mac);
            if (last == mac_last_ip_.end() || last.value() != src_num) {
                mac_last_ip_.insert(mac, src_num);
                mac_ipv4s_[mac].insert(ip_src);
                ipv4_mac_.insert(ip_src, mac);
            }
        }
    } else {
        const QString v6_src = pinfo->net_src.type == AT_IPv6 ? addressText(pinfo->net_src) : QString();
        if (v6_src.isEmpty()) {
            return;
        }
        src = hostForIpv6(v6_src, mac);
        const QString v6_dst = pinfo->net_dst.type == AT_IPv6 ? addressText(pinfo->net_dst) : QString();
        if (!v6_dst.isEmpty() && !v6_dst.startsWith(QLatin1String("ff"))) {
            dst = hostForIpv6(v6_dst, QString());
        }
        ttl = firstInt(edt, f_.ipv6_hlim);
    }

    /* Traffic and protocol counts. */
    for (int h : { src, dst }) {
        if (h < 0) continue;
        HostRecord &host = hosts_[h];
        if (host.firstFrame == 0) host.firstFrame = frame;
        host.lastFrame = frame;
        if (!top_is_lower && last_layer_[h] != layer->id) {
            last_layer_[h] = layer->id;
            if (!host.protocols.contains(top_upper)) {
                host.protocols << top_upper;
            }
        }
    }
    hosts_[src].packetsSent++;
    hosts_[src].bytesSent += length;
    if (dst >= 0) {
        hosts_[dst].packetsReceived++;
        hosts_[dst].bytesReceived += length;
    }

    /* TCP: SYN-ACK means the sender listens on its port; SYN and
     * SYN-ACK both carry the stack's default options, which hint at
     * the operating system. */
    const int tcp_src = pinfo->ptype == PT_TCP ? static_cast<int>(pinfo->srcport) : -1;
    if (tcp_src >= 0) {
        const int flags = peek.tcpParsed ? peek.tcpFlags : firstInt(edt, f_.tcp_flags, 0);
        const bool syn = flags & 0x02, ack = flags & 0x10;
        if (syn && peek.tcpParsed) {
            /* Each host repeats the same handshake; describe it once. */
            const quint64 key = (static_cast<quint64>(src) << 40) ^ (static_cast<quint64>(peek.ttl & 0xff) << 32) ^
                                (static_cast<quint64>(peek.window & 0xffff) << 16) ^ static_cast<quint64>(peek.mss & 0xffff) ^
                                (static_cast<quint64>(peek.wscale & 0x1f) << 56) ^ (peek.timestamps ? (1ULL << 63) : 0);
            if (!syn_seen_.contains(key)) {
                syn_seen_.insert(key);
                addEvidence(src, tcpEvidence(peek.ttl, peek.window, peek.mss, peek.wscale, peek.timestamps, frame));
            }
        } else if (syn) {
            QStringList kinds = values(edt, f_.tcp_option_kind);
            const bool timestamps = kinds.contains(QLatin1String("8")) ||
                                    kinds.filter(QStringLiteral("Time Stamp")).size() > 0;
            addEvidence(src, tcpEvidence(ttl, firstInt(edt, f_.tcp_window), firstInt(edt, f_.tcp_mss),
                                         firstInt(edt, f_.tcp_wscale), timestamps, frame));
        }
        if (syn && ack) {
            serviceFor(src, QStringLiteral("TCP"), static_cast<quint16>(tcp_src), frame);
        }
        /* Name the service after what the engine decoded in replies. */
        for (ServiceRecord &s : hosts_[src].services) {
            if (s.transport == QLatin1String("TCP") && s.port == tcp_src) {
                s.packets++;
                if (s.service.isEmpty() && (peek.tcpPayload >= 0 ? peek.tcpPayload : firstInt(edt, f_.tcp_len, 0)) > 0 && !top_is_lower) {
                    s.service = top_upper;
                }
                const QString server = first(edt, f_.http_server);
                const QString ssh = first(edt, f_.ssh_protocol);
                if (s.banner.isEmpty() && !server.isEmpty()) s.banner = server;
                if (s.banner.isEmpty() && !ssh.isEmpty()) s.banner = ssh;
            }
        }
    }

    /* UDP services: replies from a low port, or DNS responses. */
    const int udp_src = pinfo->ptype == PT_UDP ? static_cast<int>(pinfo->srcport) : -1;
    if (udp_src >= 0) {
        const int udp_dst = static_cast<int>(pinfo->destport);
        const bool dns_response = firstInt(edt, f_.dns_response, 0) == 1;
        if ((udp_src < 1024 && udp_dst >= 1024 && !top_is_lower) || (dns_response && udp_src == 53)) {
            ServiceRecord &s = serviceFor(src, QStringLiteral("UDP"), static_cast<quint16>(udp_src), frame);
            s.packets++;
            if (s.service.isEmpty()) {
                s.service = top_upper;
            }
        }
    }

    /* Application-level evidence and names. */
    const QString agent = first(edt, f_.http_user_agent);
    if (!agent.isEmpty()) {
        addEvidence(src, userAgentEvidence(agent, frame));
    }
    const QString server = first(edt, f_.http_server);
    if (!server.isEmpty()) {
        addEvidence(src, serverHeaderEvidence(server, frame));
    }
    const QString ssh = first(edt, f_.ssh_protocol);
    if (!ssh.isEmpty()) {
        addEvidence(src, sshBannerEvidence(ssh, frame));
    }
    const QString smb_os = first(edt, f_.smb_native_os);
    if (!smb_os.isEmpty()) {
        OsEvidence e;
        e.os = smb_os;
        e.family = smb_os.contains(QLatin1String("Windows"), Qt::CaseInsensitive) ? QStringLiteral("Windows")
                 : smb_os.contains(QLatin1String("Unix"), Qt::CaseInsensitive) ? QStringLiteral("Linux") : smb_os;
        e.source = QStringLiteral("SMB native OS");
        e.detail = smb_os;
        e.weight = 3;
        e.frame = frame;
        addEvidence(src, { e });
    }

    const QString dhcp_name = first(edt, f_.dhcp_hostname);
    const QString dhcp_vendor = first(edt, f_.dhcp_vendor);
    if (!dhcp_name.isEmpty() || !dhcp_vendor.isEmpty()) {
        /* DHCP clients often have no address yet: find them by MAC. */
        const QString client_mac = first(edt, f_.dhcp_client_mac);
        int client = (ip_src.isEmpty() || ip_src == QLatin1String("0.0.0.0")) ? -1 : src;
        if (client < 0 && !client_mac.isEmpty()) {
            QString owner = arp_owner_.value(client_mac);
            if (owner.isEmpty() && mac_last_ip_.contains(client_mac)) {
                owner = ipv4Text(mac_last_ip_.value(client_mac));
            }
            if (!owner.isEmpty()) client = hostForIpv4(owner);
        }
        if (client >= 0) {
            setName(client, dhcp_name, QStringLiteral("DHCP"), RankDhcp);
            if (!dhcp_vendor.isEmpty()) addEvidence(client, dhcpVendorEvidence(dhcp_vendor, frame));
        }
    }
    for (const QString &router : values(edt, f_.dhcp_router)) {
        dhcp_routers_.insert(router);
    }

    const QString nbns = first(edt, f_.nbns_name);
    if (!nbns.isEmpty()) {
        setName(src, nbns.section(QLatin1Char('<'), 0, 0).trimmed(), QStringLiteral("NetBIOS"), RankNbns);
    }

    const QStringList answers = values(edt, f_.dns_a);
    if (!answers.isEmpty()) {
        const QStringList names = values(edt, f_.dns_resp_name);
        /* Pair A records with the names they answer, from the end, so
         * CNAME records earlier in the list do not shift the pairing. */
        for (int i = 0; i < answers.size(); i++) {
            const int name_index = static_cast<int>(names.size()) - static_cast<int>(answers.size()) + i;
            if (name_index >= 0) {
                const QString short_name = names[name_index].section(QLatin1Char('.'), 0, 0).toUpper();
                setName(hostForIpv4(answers[i]), short_name, QStringLiteral("DNS"), RankDns);
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Operating system evidence                                           */

static int initialTtl(int ttl)
{
    if (ttl <= 0) return 0;
    if (ttl <= 64) return 64;
    if (ttl <= 128) return 128;
    return 255;
}

QVector<OsEvidence> HostInventory::tcpEvidence(int ttl, int window, int mss, int wscale, bool timestamps, quint32 frame)
{
    QVector<OsEvidence> out;
    const int start = initialTtl(ttl);
    if (start == 0) {
        return out;
    }
    OsEvidence e;
    e.source = QStringLiteral("TCP handshake");
    e.frame = frame;
    e.detail = QStringLiteral("TTL %1 (starts at %2), window %3").arg(ttl).arg(start).arg(window);
    if (mss > 0) e.detail += QStringLiteral(", MSS %1").arg(mss);
    if (wscale >= 0) e.detail += QStringLiteral(", scale %1").arg(wscale);
    e.detail += timestamps ? QStringLiteral(", timestamps") : QStringLiteral(", no timestamps");

    if (start == 128) {
        e.family = QStringLiteral("Windows");
        if (window == 64240 && wscale == 8 && !timestamps) {
            e.os = QStringLiteral("Windows 10/11");
            e.weight = 2;
        } else {
            e.os = QStringLiteral("Windows");
            e.weight = 1;
        }
    } else if (start == 64) {
        if (window == 65535 && wscale == 6 && timestamps) {
            e.family = QStringLiteral("macOS");
            e.os = QStringLiteral("macOS / iOS");
            e.weight = 2;
        } else if (timestamps && wscale >= 7) {
            e.family = QStringLiteral("Linux");
            e.os = QStringLiteral("Linux");
            e.weight = 2;
        } else {
            e.family = QStringLiteral("Linux");
            e.os = QStringLiteral("Linux / Unix");
            e.weight = 1;
        }
    } else {
        e.family = QStringLiteral("Embedded");
        e.os = QStringLiteral("Network device / embedded");
        e.weight = 1;
    }
    out << e;
    return out;
}

static OsEvidence makeEvidence(const QString &os, const QString &family, const QString &source,
                               const QString &detail, int weight, quint32 frame)
{
    OsEvidence e;
    e.os = os;
    e.family = family;
    e.source = source;
    e.detail = detail;
    e.weight = weight;
    e.frame = frame;
    return e;
}

QVector<OsEvidence> HostInventory::userAgentEvidence(const QString &agent, quint32 frame)
{
    const QString src = QStringLiteral("HTTP User-Agent");
    if (agent.contains(QLatin1String("Windows NT 10.0")))
        return { makeEvidence(QStringLiteral("Windows 10/11"), QStringLiteral("Windows"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Windows NT 6.3")))
        return { makeEvidence(QStringLiteral("Windows 8.1"), QStringLiteral("Windows"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Windows NT 6.1")))
        return { makeEvidence(QStringLiteral("Windows 7"), QStringLiteral("Windows"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Windows")))
        return { makeEvidence(QStringLiteral("Windows"), QStringLiteral("Windows"), src, agent, 1, frame) };
    if (agent.contains(QLatin1String("iPhone")) || agent.contains(QLatin1String("iPad")))
        return { makeEvidence(QStringLiteral("iOS"), QStringLiteral("macOS"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Mac OS X")) || agent.contains(QLatin1String("Macintosh")))
        return { makeEvidence(QStringLiteral("macOS"), QStringLiteral("macOS"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Android")))
        return { makeEvidence(QStringLiteral("Android"), QStringLiteral("Linux"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Ubuntu")))
        return { makeEvidence(QStringLiteral("Ubuntu Linux"), QStringLiteral("Linux"), src, agent, 2, frame) };
    if (agent.contains(QLatin1String("Linux")) || agent.contains(QLatin1String("X11")))
        return { makeEvidence(QStringLiteral("Linux"), QStringLiteral("Linux"), src, agent, 1, frame) };
    return {};
}

QVector<OsEvidence> HostInventory::serverHeaderEvidence(const QString &server, quint32 frame)
{
    const QString src = QStringLiteral("HTTP Server header");
    if (server.contains(QLatin1String("(Ubuntu)")))
        return { makeEvidence(QStringLiteral("Ubuntu Linux"), QStringLiteral("Linux"), src, server, 2, frame) };
    if (server.contains(QLatin1String("(Debian)")))
        return { makeEvidence(QStringLiteral("Debian Linux"), QStringLiteral("Linux"), src, server, 2, frame) };
    if (server.contains(QLatin1String("(Red Hat)")) || server.contains(QLatin1String("(CentOS)")) ||
        server.contains(QLatin1String("(Rocky")))
        return { makeEvidence(QStringLiteral("Red Hat family Linux"), QStringLiteral("Linux"), src, server, 2, frame) };
    if (server.contains(QLatin1String("Microsoft-IIS/10.0")))
        return { makeEvidence(QStringLiteral("Windows Server 2016 or later"), QStringLiteral("Windows"), src, server, 2, frame) };
    if (server.contains(QLatin1String("Microsoft-IIS")) || server.contains(QLatin1String("(Win")))
        return { makeEvidence(QStringLiteral("Windows Server"), QStringLiteral("Windows"), src, server, 1, frame) };
    return {};
}

QVector<OsEvidence> HostInventory::sshBannerEvidence(const QString &banner, quint32 frame)
{
    const QString src = QStringLiteral("SSH banner");
    /* OpenSSH package versions map to distribution releases. */
    static const struct { const char *pattern; const char *os; const char *family; } releases[] = {
        { "OpenSSH_9.6p1 Ubuntu",  "Ubuntu 24.04", "Linux" },
        { "OpenSSH_8.9p1 Ubuntu",  "Ubuntu 22.04", "Linux" },
        { "OpenSSH_8.2p1 Ubuntu",  "Ubuntu 20.04", "Linux" },
        { "OpenSSH_9.2p1 Debian",  "Debian 12",    "Linux" },
        { "OpenSSH_8.4p1 Debian",  "Debian 11",    "Linux" },
        { "OpenSSH_for_Windows",   "Windows",      "Windows" },
    };
    for (const auto &r : releases) {
        if (banner.contains(QLatin1String(r.pattern)))
            return { makeEvidence(QString::fromLatin1(r.os), QString::fromLatin1(r.family), src, banner.trimmed(), 3, frame) };
    }
    if (banner.contains(QLatin1String("Ubuntu")))
        return { makeEvidence(QStringLiteral("Ubuntu Linux"), QStringLiteral("Linux"), src, banner.trimmed(), 2, frame) };
    if (banner.contains(QLatin1String("Debian")))
        return { makeEvidence(QStringLiteral("Debian Linux"), QStringLiteral("Linux"), src, banner.trimmed(), 2, frame) };
    if (banner.contains(QLatin1String("Cisco")))
        return { makeEvidence(QStringLiteral("Cisco IOS"), QStringLiteral("Embedded"), src, banner.trimmed(), 2, frame) };
    return {};
}

QVector<OsEvidence> HostInventory::dhcpVendorEvidence(const QString &vendor, quint32 frame)
{
    const QString src = QStringLiteral("DHCP vendor class");
    if (vendor.startsWith(QLatin1String("MSFT")))
        return { makeEvidence(QStringLiteral("Windows"), QStringLiteral("Windows"), src, vendor, 2, frame) };
    if (vendor.startsWith(QLatin1String("android-dhcp")))
        return { makeEvidence(QStringLiteral("Android"), QStringLiteral("Linux"), src, vendor, 2, frame) };
    if (vendor.startsWith(QLatin1String("dhcpcd")) || vendor.startsWith(QLatin1String("udhcp")))
        return { makeEvidence(QStringLiteral("Linux"), QStringLiteral("Linux"), src, vendor, 1, frame) };
    return {};
}

/* Pick the family with the most evidence, then its most specific label.
 * Each kind of evidence counts once, so a chatty host does not look
 * more certain than a quiet one. */
void HostInventory::chooseOs(HostRecord &host)
{
    host.os.clear();
    host.osFamily.clear();
    host.osConfidence = 0;
    if (host.osEvidence.isEmpty()) {
        return;
    }

    QMap<QString, int> family_score;
    for (const OsEvidence &e : host.osEvidence) {
        family_score[e.family] += e.weight;
    }
    QString best_family;
    int best = 0, runner_up = 0;
    for (auto it = family_score.constBegin(); it != family_score.constEnd(); ++it) {
        if (it.value() > best) {
            runner_up = best;
            best = it.value();
            best_family = it.key();
        } else if (it.value() > runner_up) {
            runner_up = it.value();
        }
    }

    /* Most specific label: highest weight, then one naming a version. */
    static const QRegularExpression has_version(QStringLiteral("\\d"));
    const OsEvidence *pick = nullptr;
    for (const OsEvidence &e : host.osEvidence) {
        if (e.family != best_family) continue;
        /* On a tie, what the host says about itself (banners, headers)
         * beats what its TCP stack suggests. */
        const bool from_stack = e.source == QLatin1String("TCP handshake");
        const bool pick_from_stack = pick && pick->source == QLatin1String("TCP handshake");
        if (!pick || e.weight > pick->weight ||
            (e.weight == pick->weight && pick_from_stack && !from_stack) ||
            (e.weight == pick->weight && from_stack == pick_from_stack &&
             e.os.contains(has_version) && !pick->os.contains(has_version))) {
            pick = &e;
        }
    }

    host.osFamily = best_family;
    host.os = pick ? pick->os : best_family;
    host.osConfidence = best >= 5 ? 3 : best >= 3 ? 2 : 1;
    if (runner_up * 10 >= best * 7 && host.osConfidence > 1) {
        host.osConfidence--;  /* another family is nearly as likely */
    }
}

HostInventorySnapshot HostInventory::snapshot() const
{
    HostInventorySnapshot snap;
    for (const HostRecord &host : hosts_) {
        /* DHCP clients without an address yet send from 0.0.0.0. */
        if (host.ipv4 != QLatin1String("0.0.0.0")) {
            snap.hosts.append(host);
        }
    }

    QSet<QString> routers;
    for (auto it = mac_ipv4s_.constBegin(); it != mac_ipv4s_.constEnd(); ++it) {
        if (it.value().size() > router_ip_threshold) {
            routers.insert(it.key());
        }
    }

    for (HostRecord &host : snap.hosts) {
        if (!host.ipv4.isEmpty()) {
            const QString mac = ipv4_mac_.value(host.ipv4);
            if (!mac.isEmpty()) {
                if (!routers.contains(mac)) {
                    host.mac = mac;
                } else if (arp_owner_.value(mac) == host.ipv4) {
                    host.mac = mac;       /* the router itself */
                    host.isRouter = true;
                }
            }
            if (dhcp_routers_.contains(host.ipv4)) {
                host.isRouter = true;
            }
        }
        if (!host.mac.isEmpty()) {
            host.vendor = macVendor(host.mac);
        }
        if (host.isRouter && host.name.isEmpty()) {
            host.name = QStringLiteral("Gateway");
            host.nameSource = QStringLiteral("Routing");
        }
        std::sort(host.services.begin(), host.services.end(), [](const ServiceRecord &a, const ServiceRecord &b) {
            return a.port < b.port;
        });
        chooseOs(host);
    }

    /* Subnets, with a suggested name from what is inside. */
    QMap<QString, QVector<const HostRecord *>> groups;
    for (const HostRecord &host : snap.hosts) {
        groups[host.subnet].append(&host);
    }
    for (auto it = groups.constBegin(); it != groups.constEnd(); ++it) {
        SubnetRecord subnet;
        subnet.cidr = it.key();
        subnet.hostCount = static_cast<int>(it.value().size());
        int servers = 0, embedded = 0, desktops = 0, routers_in = 0;
        for (const HostRecord *h : it.value()) {
            if (!h->osFamily.isEmpty() && !subnet.osFamilies.contains(h->osFamily)) {
                subnet.osFamilies << h->osFamily;
            }
            if (h->isRouter) routers_in++;
            if (!h->services.isEmpty()) servers++;
            if (h->osFamily == QLatin1String("Embedded")) embedded++;
            if (h->services.isEmpty() && (h->osFamily == QLatin1String("Windows") || h->osFamily == QLatin1String("macOS"))) desktops++;
        }
        const int n = subnet.hostCount;
        if (subnet.cidr == QLatin1String("Internet")) subnet.suggestedName = QStringLiteral("Internet");
        else if (embedded * 10 >= n * 6) subnet.suggestedName = QStringLiteral("IoT devices");
        else if (servers * 10 >= n * 6) subnet.suggestedName = QStringLiteral("Servers");
        else if (desktops * 10 >= n * 6) subnet.suggestedName = QStringLiteral("Workstations");
        else if (routers_in > 0) subnet.suggestedName = QStringLiteral("Core");
        snap.subnets.append(subnet);
    }
    return snap;
}
