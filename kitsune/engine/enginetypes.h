/* enginetypes.h
 *
 * Kitsune - plain data passed between the engine thread and the GUI.
 * Nothing here points into libwireshark memory, so it can cross
 * threads and outlive the dissection that produced it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_ENGINETYPES_H
#define KITSUNE_ENGINETYPES_H

#include <QByteArray>
#include <QList>
#include <QMetaType>
#include <QSharedPointer>
#include <QString>
#include <QStringList>
#include <QVector>

/* One row of the packet list. */
struct PacketRow {
    quint32 frame = 0;
    QStringList columns;
};

/* One item of the packet details tree. */
struct ProtoNode {
    QString label;
    QString field;          /* filter field name, e.g. "ip.src" */
    QString filterValue;    /* value as a display filter expression */
    int start = -1;         /* byte range in the frame, -1 if not in it */
    int length = 0;
    int severity = 0;       /* 0 none, 1 chat, 2 note, 3 warning, 4 error */
    bool isProtocol = false;
    QVector<QSharedPointer<ProtoNode>> children;
    ProtoNode *parent = nullptr;
};
using ProtoNodePtr = QSharedPointer<ProtoNode>;

/* A dissected packet, for the details and bytes views. */
struct PacketDetails {
    quint32 frame = 0;
    ProtoNodePtr root;
    QByteArray bytes;
};

/* One piece of evidence for an operating system guess. */
struct OsEvidence {
    QString os;             /* e.g. "Windows 10/11", "Ubuntu 24.04" */
    QString family;         /* e.g. "Windows", "Linux", "macOS", "Embedded" */
    QString source;         /* e.g. "TCP SYN", "HTTP User-Agent" */
    QString detail;         /* what was seen, e.g. "TTL 128, window 64240" */
    int weight = 1;         /* 1 weak, 2 medium, 3 strong */
    quint32 frame = 0;      /* first packet that showed it */
};

/* A service a host offers. */
struct ServiceRecord {
    QString transport;      /* "TCP" or "UDP" */
    quint16 port = 0;
    QString service;        /* protocol the engine decoded, e.g. "HTTP" */
    QString banner;         /* e.g. "nginx/1.24.0 (Ubuntu)" */
    quint32 firstFrame = 0;
    quint64 packets = 0;
};

/* Everything learned about one host. */
struct HostRecord {
    QString name;           /* from DHCP, NetBIOS, mDNS or DNS */
    QString nameSource;
    QString ipv4;
    QStringList ipv6;
    QString mac;
    QString vendor;         /* from the MAC's OUI */
    QString subnet;         /* e.g. "192.168.20.0/24" */
    bool isRouter = false;  /* one MAC seen with many IPs */
    QString os;             /* best guess */
    QString osFamily;
    int osConfidence = 0;   /* 0 unknown, 1 low, 2 medium, 3 high */
    QVector<OsEvidence> osEvidence;
    QVector<ServiceRecord> services;
    QStringList protocols;  /* protocols seen to or from the host */
    quint64 packetsSent = 0;
    quint64 packetsReceived = 0;
    quint64 bytesSent = 0;
    quint64 bytesReceived = 0;
    quint32 firstFrame = 0;
    quint32 lastFrame = 0;
};

/* A group of hosts in one subnet. */
struct SubnetRecord {
    QString cidr;
    QString suggestedName;  /* e.g. "Servers?", from what's inside */
    int hostCount = 0;
    QStringList osFamilies;
};

struct HostInventorySnapshot {
    QVector<HostRecord> hosts;
    QVector<SubnetRecord> subnets;
};

Q_DECLARE_METATYPE(PacketRow)
Q_DECLARE_METATYPE(QVector<PacketRow>)
Q_DECLARE_METATYPE(PacketDetails)
Q_DECLARE_METATYPE(HostInventorySnapshot)
Q_DECLARE_METATYPE(QVector<quint32>)

#endif // KITSUNE_ENGINETYPES_H
