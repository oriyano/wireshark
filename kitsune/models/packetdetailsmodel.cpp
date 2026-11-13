/* packetdetailsmodel.cpp
 *
 * Kitsune - packet details tree and packet bytes models.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packetdetailsmodel.h"

#include "engine/captureengine.h"

PacketDetailsModel::PacketDetailsModel(CaptureEngine *engine, QObject *parent) :
    QAbstractItemModel(parent)
{
    connect(engine, &CaptureEngine::detailsReady, this, &PacketDetailsModel::onDetailsReady);
}

ProtoNode *PacketDetailsModel::nodeFor(const QModelIndex &index) const
{
    if (!index.isValid()) {
        return details_.root.data();
    }
    return static_cast<ProtoNode *>(index.internalPointer());
}

QModelIndex PacketDetailsModel::index(int row, int column, const QModelIndex &parent) const
{
    ProtoNode *parent_node = nodeFor(parent);
    if (!parent_node || column != 0 || row < 0 || row >= parent_node->children.size()) {
        return QModelIndex();
    }
    return createIndex(row, 0, parent_node->children[row].data());
}

QModelIndex PacketDetailsModel::parent(const QModelIndex &child) const
{
    ProtoNode *node = nodeFor(child);
    if (!child.isValid() || !node || !node->parent || node->parent == details_.root.data()) {
        return QModelIndex();
    }
    ProtoNode *parent_node = node->parent;
    ProtoNode *grandparent = parent_node->parent;
    if (!grandparent) {
        return QModelIndex();
    }
    for (int i = 0; i < grandparent->children.size(); i++) {
        if (grandparent->children[i].data() == parent_node) {
            return createIndex(i, 0, parent_node);
        }
    }
    return QModelIndex();
}

int PacketDetailsModel::rowCount(const QModelIndex &parent) const
{
    ProtoNode *node = nodeFor(parent);
    return node ? static_cast<int>(node->children.size()) : 0;
}

int PacketDetailsModel::columnCount(const QModelIndex &) const
{
    return 1;
}

QVariant PacketDetailsModel::data(const QModelIndex &index, int role) const
{
    ProtoNode *node = index.isValid() ? nodeFor(index) : nullptr;
    if (!node) {
        return QVariant();
    }
    switch (role) {
    case Qt::DisplayRole: return node->label;
    case FieldRole: return node->field;
    case FilterRole: return filterFor(index);
    case StartRole: return node->start;
    case LengthRole: return node->length;
    case SeverityRole: return node->severity;
    case IsProtocolRole: return node->isProtocol;
    default: return QVariant();
    }
}

QHash<int, QByteArray> PacketDetailsModel::roleNames() const
{
    QHash<int, QByteArray> names = QAbstractItemModel::roleNames();
    names.insert(FieldRole, "field");
    names.insert(FilterRole, "filter");
    names.insert(StartRole, "byteStart");
    names.insert(LengthRole, "byteLength");
    names.insert(SeverityRole, "severity");
    names.insert(IsProtocolRole, "isProtocol");
    return names;
}

QString PacketDetailsModel::filterFor(const QModelIndex &index) const
{
    ProtoNode *node = index.isValid() ? nodeFor(index) : nullptr;
    if (!node || node->field.isEmpty()) {
        return QString();
    }
    if (node->isProtocol || node->filterValue.isEmpty()) {
        return node->field;
    }
    return QStringLiteral("%1 == %2").arg(node->field, node->filterValue);
}

void PacketDetailsModel::onDetailsReady(const PacketDetails &details)
{
    beginResetModel();
    details_ = details;
    if (!details_.root) {
        details_.root = ProtoNodePtr::create();
    }
    endResetModel();
    emit detailsChanged();
}

/* ------------------------------------------------------------------ */

PacketBytesModel::PacketBytesModel(PacketDetailsModel *details, QObject *parent) :
    QAbstractListModel(parent),
    details_(details)
{
    connect(details_, &PacketDetailsModel::detailsChanged, this, &PacketBytesModel::onDetailsChanged);
}

int PacketBytesModel::rowCount(const QModelIndex &parent) const
{
    if (parent.isValid()) {
        return 0;
    }
    return (static_cast<int>(bytes_.size()) + bytes_per_row - 1) / bytes_per_row;
}

int PacketBytesModel::byteAt(int offset) const
{
    return offset >= 0 && offset < bytes_.size() ? static_cast<unsigned char>(bytes_[offset]) : -1;
}

QVariant PacketBytesModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return QVariant();
    }
    const int start = index.row() * bytes_per_row;
    const int count = qMin(bytes_per_row, static_cast<int>(bytes_.size()) - start);
    switch (role) {
    case OffsetRole:
        return QStringLiteral("%1").arg(start, 4, 16, QLatin1Char('0'));
    case RowStartRole:
        return start;
    case HexRole: {
        QStringList hex;
        for (int i = 0; i < count; i++) {
            hex << QStringLiteral("%1").arg(static_cast<unsigned char>(bytes_[start + i]), 2, 16, QLatin1Char('0'));
        }
        return hex;
    }
    case AsciiRole: {
        QString ascii;
        for (int i = 0; i < count; i++) {
            const unsigned char c = static_cast<unsigned char>(bytes_[start + i]);
            ascii += (c >= 0x20 && c < 0x7f) ? QChar(c) : QChar('.');
        }
        return ascii;
    }
    default:
        return QVariant();
    }
}

QHash<int, QByteArray> PacketBytesModel::roleNames() const
{
    return {
        { OffsetRole, "offset" },
        { HexRole, "hex" },
        { AsciiRole, "ascii" },
        { RowStartRole, "rowStart" }
    };
}

void PacketBytesModel::onDetailsChanged()
{
    beginResetModel();
    bytes_ = details_->details().bytes;
    endResetModel();
    emit bytesChanged();
}
