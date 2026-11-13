/* hostmodels.h
 *
 * Kitsune - list models over the host inventory: subnets, and the
 * hosts in one subnet (or all of them).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_HOSTMODELS_H
#define KITSUNE_HOSTMODELS_H

#include <QAbstractListModel>
#include <QVariantMap>

#include "engine/enginetypes.h"

class CaptureEngine;

class SubnetListModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum Roles { CidrRole = Qt::UserRole + 1, SuggestedNameRole, HostCountRole, OsFamiliesRole };

    explicit SubnetListModel(CaptureEngine *engine, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    int count() const { return static_cast<int>(subnets_.size()); }
    Q_INVOKABLE QString suggestedName(const QString &cidr) const;

signals:
    void countChanged();

private slots:
    void onInventoryChanged();

private:
    CaptureEngine *engine_;
    QVector<SubnetRecord> subnets_;
};

class HostListModel : public QAbstractListModel
{
    Q_OBJECT
    /* Empty shows every host; otherwise only hosts in this subnet. */
    Q_PROPERTY(QString subnet READ subnet WRITE setSubnet NOTIFY subnetChanged)
    Q_PROPERTY(int count READ count NOTIFY countChanged)
    Q_PROPERTY(int totalServices READ totalServices NOTIFY countChanged)
    Q_PROPERTY(int osTypes READ osTypes NOTIFY countChanged)

public:
    enum Roles {
        NameRole = Qt::UserRole + 1, Ipv4Role, Ipv6Role, MacRole, VendorRole, SubnetRole,
        OsRole, OsFamilyRole, OsConfidenceRole, OpenPortsRole, ServicesRole, IsRouterRole,
        PacketsRole, BytesRole
    };

    explicit HostListModel(CaptureEngine *engine, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

    QString subnet() const { return subnet_; }
    void setSubnet(const QString &subnet);
    int count() const { return static_cast<int>(rows_.size()); }
    int totalServices() const;
    int osTypes() const;

    /* Everything about one host, for the host panel: services, OS
     * evidence, addresses. */
    Q_INVOKABLE QVariantMap host(int row) const;

signals:
    void subnetChanged();
    void countChanged();

private slots:
    void rebuild();

private:
    CaptureEngine *engine_;
    QString subnet_;
    QVector<int> rows_;     /* indexes into the engine's inventory */
};

#endif // KITSUNE_HOSTMODELS_H
