/* packetlistmodel.cpp
 *
 * Kitsune - table model for the packet list.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packetlistmodel.h"

#include "engine/captureengine.h"

/* Enough rows for several screens of scrolling in both directions. */
static const int row_cache_size = 4000;

PacketListModel::PacketListModel(CaptureEngine *engine, QObject *parent) :
    QAbstractTableModel(parent),
    engine_(engine),
    row_count_(0),
    protocol_column_(-1),
    cache_(row_cache_size),
    dissected_rows_(0)
{
    for (int i = 0; i < engine_->columnCount(); i++) {
        if (engine_->columnTitle(i) == QLatin1String("Protocol")) {
            protocol_column_ = i;
            break;
        }
    }

    connect(engine_, &CaptureEngine::fileChanged, this, &PacketListModel::onFileChanged);
    connect(engine_, &CaptureEngine::loaded, this, &PacketListModel::onLoaded);
}

int PacketListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : row_count_;
}

int PacketListModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : engine_->columnCount();
}

QString PacketListModel::columnTitle(int column) const
{
    return engine_->columnTitle(column);
}

const QStringList *PacketListModel::rowColumns(int row) const
{
    if (QStringList *cached = cache_.object(row)) {
        return cached;
    }

    QStringList *columns = new QStringList();
    if (!engine_->dissectColumns(static_cast<uint32_t>(row) + 1, *columns)) {
        delete columns;
        return nullptr;
    }
    dissected_rows_++;
    cache_.insert(row, columns);
    return columns;
}

QVariant PacketListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= row_count_) {
        return QVariant();
    }

    switch (role) {
    case Qt::DisplayRole: {
        const QStringList *columns = rowColumns(index.row());
        return columns ? columns->value(index.column()) : QVariant();
    }
    case ProtocolRole: {
        if (protocol_column_ < 0) {
            return QString();
        }
        const QStringList *columns = rowColumns(index.row());
        return columns ? columns->value(protocol_column_) : QVariant();
    }
    case FrameNumberRole:
        return index.row() + 1;
    default:
        return QVariant();
    }
}

QVariant PacketListModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole) {
        return QVariant();
    }
    if (orientation == Qt::Horizontal) {
        return engine_->columnTitle(section);
    }
    return section + 1;
}

QHash<int, QByteArray> PacketListModel::roleNames() const
{
    QHash<int, QByteArray> names = QAbstractTableModel::roleNames();
    names.insert(ProtocolRole, "protocol");
    names.insert(FrameNumberRole, "frameNumber");
    return names;
}

void PacketListModel::onFileChanged()
{
    beginResetModel();
    cache_.clear();
    row_count_ = 0;
    dissected_rows_ = 0;
    endResetModel();
}

void PacketListModel::onLoaded()
{
    beginResetModel();
    cache_.clear();
    row_count_ = engine_->packetCount();
    endResetModel();
}
