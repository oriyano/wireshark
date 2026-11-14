/* syncpipe.h
 *
 * Kitsune - talking to dumpcap: its command line, its sync pipe
 * messages and its interface list.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_SYNCPIPE_H
#define KITSUNE_SYNCPIPE_H

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVector>

namespace SyncPipe {

/* Message types, from capture/sync_pipe.h. */
const char sp_file = 'F';           /* the file dumpcap is now writing */
const char sp_error = 'E';          /* holds two messages: error and hint */
const char sp_bad_filter = 'B';     /* "<interface>:<message>" */
const char sp_packet_count = 'P';   /* packets added since the last count */
const char sp_drops = 'D';          /* packets dropped so far */
const char sp_success = 'S';

/* Each message: a type byte, a 3-byte big-endian length, then the body.
   Strings include their terminating NUL; it is removed here, except in
   errors, whose body is two whole messages. */
struct Message {
    char type;
    QByteArray body;
};

/* Take every complete message off the front of buffer. */
QVector<Message> parseMessages(QByteArray &buffer);

/* The text of an error message's two parts, error then hint, without
   empty parts. */
QStringList errorText(const QByteArray &body);

/* "dumpcap -D" output, as {name, description, label} maps. */
QVariantList parseInterfaceList(const QString &output);

/* The command line for one capture. */
QStringList captureArguments(const QString &interface_name, const QString &capture_filter,
                             const QString &output, bool ring_buffer, int ring_files, int ring_megabytes);

} // namespace SyncPipe

#endif // KITSUNE_SYNCPIPE_H
