/* hostmodels.cpp
 *
 * Kitsune - subnet and host list models.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "hostmodels.h"

#include <QSet>
#include <QVariantList>

#include <algorithm>

#include "engine/captureengine.h"

/* Sort IPv4 addresses numerically, others after them. */
static quint64 ipv4Key(const QString &ip)
{
    const QStringList o = ip.split(QLatin1Char('.'));
    if (o.size() != 4) {
        return ~0ULL;
    }
    return (o[0].toULongLong() << 24) | (o[1].toULongLong() << 16) | (o[2].toULongLong() << 8) | o[3].toULongLong();
}

SubnetListModel::SubnetListModel(CaptureEngine *engine, QObject *parent) :
    QAbstractListModel(parent),
    engine_(engine)
{
    connect(engine_, &CaptureEngine::inventoryChanged, this, &SubnetListModel::onInventoryChanged);
}

int SubnetListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(subnets_.size());
}

QVariant SubnetListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= subnets_.size()) {
        return QVariant();
    }
    const SubnetRecord &s = subnets_[index.row()];
    switch (role) {
    case Qt::DisplayRole:
    case CidrRole: return s.cidr;
    case SuggestedNameRole: return s.suggestedName;
    case HostCountRole: return s.hostCount;
    case OsFamiliesRole: return s.osFamilies;
    default: return QVariant();
    }
}

QHash<int, QByteArray> SubnetListModel::roleNames() const
{
    return {
        { CidrRole, "cidr" }, { SuggestedNameRole, "suggestedName" },
        { HostCountRole, "hostCount" }, { OsFamiliesRole, "osFamilies" }
    };
}

QString SubnetListModel::suggestedName(const QString &cidr) const
{
    for (const SubnetRecord &s : subnets_) {
        if (s.cidr == cidr) {
            return s.suggestedName;
        }
    }
    return QString();
}

void SubnetListModel::onInventoryChanged()
{
    beginResetModel();
    subnets_ = engine_->inventory().subnets;
    std::sort(subnets_.begin(), subnets_.end(), [](const SubnetRecord &a, const SubnetRecord &b) {
        if ((a.cidr == QLatin1String("Internet")) != (b.cidr == QLatin1String("Internet"))) {
            return b.cidr == QLatin1String("Internet");
        }
        return ipv4Key(a.cidr.section(QLatin1Char('/'), 0, 0)) < ipv4Key(b.cidr.section(QLatin1Char('/'), 0, 0));
    });
    endResetModel();
    emit countChanged();
}

/* ------------------------------------------------------------------ */

HostListModel::HostListModel(CaptureEngine *engine, QObject *parent) :
    QAbstractListModel(parent),
    engine_(engine)
{
    connect(engine_, &CaptureEngine::inventoryChanged, this, &HostListModel::rebuild);
}

void HostListModel::setSubnet(const QString &subnet)
{
    if (subnet == subnet_) {
        return;
    }
    subnet_ = subnet;
    emit subnetChanged();
    rebuild();
}

void HostListModel::rebuild()
{
    beginResetModel();
    rows_.clear();
    const QVector<HostRecord> &hosts = engine_->inventory().hosts;
    for (int i = 0; i < hosts.size(); i++) {
        if (subnet_.isEmpty() || hosts[i].subnet == subnet_) {
            rows_.append(i);
        }
    }
    std::sort(rows_.begin(), rows_.end(), [&hosts](int a, int b) {
        return ipv4Key(hosts[a].ipv4) < ipv4Key(hosts[b].ipv4);
    });
    endResetModel();
    emit countChanged();
}

int HostListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

static QString servicesText(const HostRecord &h)
{
    QStringList names;
    for (const ServiceRecord &s : h.services) {
        const QString name = s.service.isEmpty() ? QString::number(s.port) : s.service;
        if (!names.contains(name)) {
            names << name;
        }
    }
    return names.join(QStringLiteral(", "));
}

QVariant HostListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= rows_.size()) {
        return QVariant();
    }
    const HostRecord &h = engine_->inventory().hosts[rows_[index.row()]];
    switch (role) {
    case Qt::DisplayRole:
    case NameRole: return h.name.isEmpty() ? (h.ipv4.isEmpty() ? h.ipv6.value(0) : h.ipv4) : h.name;
    case Ipv4Role: return h.ipv4;
    case Ipv6Role: return h.ipv6.join(QStringLiteral(", "));
    case MacRole: return h.mac;
    case VendorRole: return h.vendor;
    case SubnetRole: return h.subnet;
    case OsRole: return h.os;
    case OsFamilyRole: return h.osFamily;
    case OsConfidenceRole: return h.osConfidence;
    case OpenPortsRole: return static_cast<int>(h.services.size());
    case ServicesRole: return servicesText(h);
    case IsRouterRole: return h.isRouter;
    case PacketsRole: return static_cast<qint64>(h.packetsSent + h.packetsReceived);
    case BytesRole: return static_cast<qint64>(h.bytesSent + h.bytesReceived);
    default: return QVariant();
    }
}

QHash<int, QByteArray> HostListModel::roleNames() const
{
    return {
        { NameRole, "name" }, { Ipv4Role, "ipv4" }, { Ipv6Role, "ipv6" }, { MacRole, "mac" },
        { VendorRole, "vendor" }, { SubnetRole, "subnet" }, { OsRole, "os" }, { OsFamilyRole, "osFamily" },
        { OsConfidenceRole, "osConfidence" }, { OpenPortsRole, "openPorts" }, { ServicesRole, "services" },
        { IsRouterRole, "isRouter" }, { PacketsRole, "packets" }, { BytesRole, "bytes" }
    };
}

int HostListModel::totalServices() const
{
    int total = 0;
    for (int i : rows_) {
        total += static_cast<int>(engine_->inventory().hosts[i].services.size());
    }
    return total;
}

int HostListModel::osTypes() const
{
    QSet<QString> types;
    for (int i : rows_) {
        const QString &os = engine_->inventory().hosts[i].os;
        if (!os.isEmpty()) types.insert(os);
    }
    return static_cast<int>(types.size());
}

QVariantMap HostListModel::host(int row) const
{
    QVariantMap out;
    if (row < 0 || row >= rows_.size()) {
        return out;
    }
    const HostRecord &h = engine_->inventory().hosts[rows_[row]];
    out[QStringLiteral("name")] = data(index(row), NameRole);
    out[QStringLiteral("nameSource")] = h.nameSource;
    out[QStringLiteral("ipv4")] = h.ipv4;
    out[QStringLiteral("ipv6")] = h.ipv6;
    out[QStringLiteral("mac")] = h.mac;
    out[QStringLiteral("vendor")] = h.vendor;
    out[QStringLiteral("subnet")] = h.subnet;
    out[QStringLiteral("isRouter")] = h.isRouter;
    out[QStringLiteral("os")] = h.os;
    out[QStringLiteral("osFamily")] = h.osFamily;
    out[QStringLiteral("osConfidence")] = h.osConfidence;
    out[QStringLiteral("protocols")] = h.protocols;
    out[QStringLiteral("packetsSent")] = static_cast<qint64>(h.packetsSent);
    out[QStringLiteral("packetsReceived")] = static_cast<qint64>(h.packetsReceived);
    out[QStringLiteral("bytesSent")] = static_cast<qint64>(h.bytesSent);
    out[QStringLiteral("bytesReceived")] = static_cast<qint64>(h.bytesReceived);
    out[QStringLiteral("firstFrame")] = h.firstFrame;
    out[QStringLiteral("lastFrame")] = h.lastFrame;

    QVariantList services;
    for (const ServiceRecord &s : h.services) {
        services << QVariantMap {
            { QStringLiteral("transport"), s.transport }, { QStringLiteral("port"), s.port },
            { QStringLiteral("service"), s.service }, { QStringLiteral("banner"), s.banner },
            { QStringLiteral("firstFrame"), s.firstFrame }, { QStringLiteral("packets"), static_cast<qint64>(s.packets) }
        };
    }
    out[QStringLiteral("services")] = services;

    QVariantList evidence;
    for (const OsEvidence &e : h.osEvidence) {
        evidence << QVariantMap {
            { QStringLiteral("os"), e.os }, { QStringLiteral("family"), e.family },
            { QStringLiteral("source"), e.source }, { QStringLiteral("detail"), e.detail },
            { QStringLiteral("weight"), e.weight }, { QStringLiteral("frame"), e.frame }
        };
    }
    out[QStringLiteral("osEvidence")] = evidence;
    return out;
}
