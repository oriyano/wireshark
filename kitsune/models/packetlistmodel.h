/* packetlistmodel.h
 *
 * Kitsune - table model for the packet list.
 *
 * Rows are the frames that pass the display filter. A row's columns
 * are dissected only when a view asks for them: the first request
 * returns empty strings and asks the engine thread, and the row fills
 * in when the answer arrives. Recently viewed rows are cached, so a
 * view that shows 40 rows of a million-packet capture dissects about
 * 40 packets, and the interface never waits for any of them.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_PACKETLISTMODEL_H
#define KITSUNE_PACKETLISTMODEL_H

#include <QAbstractTableModel>
#include <QCache>
#include <QSet>
#include <QStringList>
#include <QVector>

#include "engine/enginetypes.h"

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
    Q_INVOKABLE int frameAt(int row) const;
    Q_INVOKABLE int rowOfFrame(int frame) const;

    /* Answer from the engine immediately instead of asynchronously.
     * For the command-line benchmark, which has no event loop running
     * between reads. */
    void setSynchronous(bool synchronous) { synchronous_ = synchronous; }

signals:
    void columnsChanged();

private slots:
    void onDisplayedFramesChanged();
    void onRowsReady(const QVector<PacketRow> &rows);
    void flushRequests();

private:
    const QStringList *rowColumns(int row) const;

    CaptureEngine *engine_;
    int protocol_column_;
    bool synchronous_ = false;
    QVector<quint32> frames_;
    mutable QCache<quint32, QStringList> cache_;
    mutable QSet<quint32> pending_;
    mutable QVector<quint32> to_request_;
    mutable bool flush_scheduled_ = false;
};

#endif // KITSUNE_PACKETLISTMODEL_H
