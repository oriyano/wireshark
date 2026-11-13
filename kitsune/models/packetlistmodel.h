/* packetlistmodel.h
 *
 * Kitsune - table model for the packet list.
 *
 * Rows are dissected only when a view asks for them, and the column
 * strings of recently viewed rows are kept in a bounded cache. A view
 * that shows 40 rows of a million-packet capture therefore dissects
 * about 40 packets, not a million.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_PACKETLISTMODEL_H
#define KITSUNE_PACKETLISTMODEL_H

#include <QAbstractTableModel>
#include <QCache>
#include <QStringList>

class CaptureEngine;

class PacketListModel : public QAbstractTableModel
{
    Q_OBJECT
    Q_PROPERTY(int protocolColumn READ protocolColumn NOTIFY columnsChanged)

public:
    enum Roles {
        ProtocolRole = Qt::UserRole + 1,
        FrameNumberRole
    };

    explicit PacketListModel(CaptureEngine *engine, QObject *parent = nullptr);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    int protocolColumn() const { return protocol_column_; }
    Q_INVOKABLE QString columnTitle(int column) const;

    /* Number of rows dissected since the file was opened (for benchmarks). */
    qint64 dissectedRows() const { return dissected_rows_; }

signals:
    void columnsChanged();

private slots:
    void onFileChanged();
    void onLoaded();

private:
    const QStringList *rowColumns(int row) const;

    CaptureEngine *engine_;
    int row_count_;
    int protocol_column_;
    mutable QCache<int, QStringList> cache_;
    mutable qint64 dissected_rows_;
};

#endif // KITSUNE_PACKETLISTMODEL_H
