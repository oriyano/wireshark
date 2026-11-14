/* packetlistmodel.cpp
 *
 * Kitsune - table model for the packet list.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packetlistmodel.h"

#include <QTimer>

#include <algorithm>

#include "engine/captureengine.h"

/* Enough rows for several screens of scrolling in both directions. */
static const int row_cache_size = 4000;

PacketListModel::PacketListModel(CaptureEngine *engine, QObject *parent) :
    QAbstractTableModel(parent),
    engine_(engine),
    protocol_column_(-1),
    cache_(row_cache_size)
{
    for (int i = 0; i < engine_->columnCount(); i++) {
        if (engine_->columnTitle(i) == QLatin1String("Protocol")) {
            protocol_column_ = i;
            break;
        }
    }

    connect(engine_, &CaptureEngine::displayedFramesChanged, this, &PacketListModel::onDisplayedFramesChanged);
    connect(engine_, &CaptureEngine::fileChanged, this, &PacketListModel::onDisplayedFramesChanged);
    connect(engine_, &CaptureEngine::rowsReady, this, &PacketListModel::onRowsReady);
    connect(engine_, &CaptureEngine::displayedFramesAppended, this, &PacketListModel::onDisplayedFramesAppended);
}

void PacketListModel::onDisplayedFramesAppended(int first, int count)
{
    const QVector<quint32> &all = engine_->displayedFrames();
    if (first != frames_.size() || first + count > all.size()) {
        onDisplayedFramesChanged();     /* out of step: start over */
        return;
    }
    beginInsertRows(QModelIndex(), first, first + count - 1);
    frames_ += all.mid(first, count);
    endInsertRows();
}

int PacketListModel::rowCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(frames_.size());
}

int PacketListModel::columnCount(const QModelIndex &parent) const
{
    return parent.isValid() ? 0 : engine_->columnCount();
}

QString PacketListModel::columnTitle(int column) const
{
    return engine_->columnTitle(column);
}

int PacketListModel::frameAt(int row) const
{
    return row >= 0 && row < frames_.size() ? static_cast<int>(frames_[row]) : 0;
}

int PacketListModel::rowOfFrame(int frame) const
{
    auto it = std::lower_bound(frames_.constBegin(), frames_.constEnd(), static_cast<quint32>(frame));
    if (it == frames_.constEnd() || *it != static_cast<quint32>(frame)) {
        return -1;
    }
    return static_cast<int>(it - frames_.constBegin());
}

const QStringList *PacketListModel::rowColumns(int row) const
{
    const quint32 frame = frames_[row];
    if (QStringList *cached = cache_.object(frame)) {
        return cached;
    }

    if (synchronous_) {
        QStringList *columns = new QStringList(engine_->columnsBlocking(frame));
        cache_.insert(frame, columns);
        return columns;
    }

    if (!pending_.contains(frame)) {
        pending_.insert(frame);
        to_request_.append(frame);
        if (!flush_scheduled_) {
            flush_scheduled_ = true;
            QTimer::singleShot(0, const_cast<PacketListModel *>(this), &PacketListModel::flushRequests);
        }
    }
    return nullptr;
}

void PacketListModel::flushRequests()
{
    flush_scheduled_ = false;
    if (to_request_.isEmpty()) {
        return;
    }
    engine_->requestRows(to_request_);
    to_request_.clear();
}

void PacketListModel::onRowsReady(const QVector<PacketRow> &rows)
{
    int first = -1, last = -1;
    for (const PacketRow &row : rows) {
        pending_.remove(row.frame);
        cache_.insert(row.frame, new QStringList(row.columns));
        const int index = rowOfFrame(static_cast<int>(row.frame));
        if (index < 0) {
            continue;
        }
        first = first < 0 ? index : qMin(first, index);
        last = qMax(last, index);
    }
    if (first >= 0) {
        emit dataChanged(index(first, 0), index(last, columnCount() - 1));
    }
}

QVariant PacketListModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid() || index.row() >= frames_.size()) {
        return QVariant();
    }

    switch (role) {
    case Qt::DisplayRole: {
        const QStringList *columns = rowColumns(index.row());
        return columns ? columns->value(index.column()) : QString();
    }
    case ProtocolRole: {
        if (protocol_column_ < 0) {
            return QString();
        }
        const QStringList *columns = rowColumns(index.row());
        return columns ? columns->value(protocol_column_) : QString();
    }
    case FrameNumberRole:
        return static_cast<int>(frames_[index.row()]);
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

void PacketListModel::onDisplayedFramesChanged()
{
    beginResetModel();
    frames_ = engine_->displayedFrames();
    if (!engine_->hasFile()) {
        cache_.clear();
    }
    pending_.clear();
    to_request_.clear();
    endResetModel();
}
