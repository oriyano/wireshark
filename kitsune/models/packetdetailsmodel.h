/* packetdetailsmodel.h
 *
 * Kitsune - tree model for the selected packet's protocol layers, and
 * a list model for its bytes as hex rows.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_PACKETDETAILSMODEL_H
#define KITSUNE_PACKETDETAILSMODEL_H

#include <QAbstractItemModel>
#include <QAbstractListModel>

#include "engine/enginetypes.h"

class CaptureEngine;

class PacketDetailsModel : public QAbstractItemModel
{
    Q_OBJECT
    Q_PROPERTY(int frame READ frame NOTIFY detailsChanged)

public:
    enum Roles {
        FieldRole = Qt::UserRole + 1,
        FilterRole,
        StartRole,
        LengthRole,
        SeverityRole,
        IsProtocolRole
    };

    explicit PacketDetailsModel(CaptureEngine *engine, QObject *parent = nullptr);

    QModelIndex index(int row, int column, const QModelIndex &parent = QModelIndex()) const override;
    QModelIndex parent(const QModelIndex &child) const override;
    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    int frame() const { return details_.frame; }
    const PacketDetails &details() const { return details_; }

    /* A display filter that matches the item, e.g. "ip.src == 10.0.0.1". */
    Q_INVOKABLE QString filterFor(const QModelIndex &index) const;

signals:
    void detailsChanged();

private slots:
    void onDetailsReady(const PacketDetails &details);

private:
    ProtoNode *nodeFor(const QModelIndex &index) const;

    PacketDetails details_;
};

class PacketBytesModel : public QAbstractListModel
{
    Q_OBJECT
    Q_PROPERTY(int byteCount READ byteCount NOTIFY bytesChanged)

public:
    enum Roles {
        OffsetRole = Qt::UserRole + 1,
        HexRole,
        AsciiRole,
        RowStartRole
    };
    static const int bytes_per_row = 16;

    explicit PacketBytesModel(PacketDetailsModel *details, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    int byteCount() const { return static_cast<int>(bytes_.size()); }
    Q_INVOKABLE int byteAt(int offset) const;

signals:
    void bytesChanged();

private slots:
    void onDetailsChanged();

private:
    PacketDetailsModel *details_;
    QByteArray bytes_;
};

#endif // KITSUNE_PACKETDETAILSMODEL_H
