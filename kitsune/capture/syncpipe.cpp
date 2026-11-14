/* syncpipe.cpp
 *
 * Kitsune - talking to dumpcap: its command line, its sync pipe
 * messages and its interface list. No engine here, so it can be tested
 * on its own.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "syncpipe.h"

#include <QRegularExpression>
#include <QVariantMap>

#include <cstring>

namespace SyncPipe {

static const int max_message_length = 512 * 1000;     /* SP_MAX_MSG_LEN */

QStringList captureArguments(const QString &interface_name, const QString &capture_filter,
                             const QString &output, bool ring_buffer, int ring_files, int ring_megabytes)
{
    QStringList args;
    args << QStringLiteral("-Z") << QStringLiteral("none")     /* report on stderr, machine-readable */
         << QStringLiteral("-i") << interface_name
         << QStringLiteral("-w") << output;
    if (!capture_filter.trimmed().isEmpty()) {
        args << QStringLiteral("-f") << capture_filter.trimmed();
    }
    if (ring_buffer) {
        args << QStringLiteral("-b") << QStringLiteral("files:%1").arg(qMax(2, ring_files))
             << QStringLiteral("-b") << QStringLiteral("filesize:%1").arg(qMax(1, ring_megabytes) * 1000);
    }
    return args;
}

QVector<Message> parseMessages(QByteArray &buffer)
{
    QVector<Message> out;
    while (buffer.size() >= 4) {
        const char type = buffer[0];
        const int length = (static_cast<unsigned char>(buffer[1]) << 16) |
                           (static_cast<unsigned char>(buffer[2]) << 8) |
                           static_cast<unsigned char>(buffer[3]);
        /* Anything else on stderr (a stray log line) isn't a message:
           skip a byte and look again. */
        if (!std::strchr("XFEWLBPDSTIQ", type) || type == '\0' || length > max_message_length) {
            buffer.remove(0, 1);
            continue;
        }
        if (buffer.size() < 4 + length) {
            break;      /* the rest of this message hasn't arrived yet */
        }
        Message m;
        m.type = type;
        m.body = buffer.mid(4, length);
        /* Strings are sent with their terminating NUL. An error holds
           whole messages, so leave those intact. */
        if (type != sp_error && m.body.endsWith('\0')) {
            m.body.chop(1);
        }
        out.append(m);
        buffer.remove(0, 4 + length);
    }
    return out;
}

QStringList errorText(const QByteArray &body)
{
    QStringList parts;
    QByteArray inner = body;
    const QVector<Message> messages = parseMessages(inner);
    for (const Message &m : messages) {
        QByteArray text = m.body;
        if (text.endsWith('\0')) {
            text.chop(1);
        }
        const QString part = QString::fromUtf8(text).simplified();
        if (!part.isEmpty()) {
            parts << part;
        }
    }
    if (messages.isEmpty() && !body.isEmpty()) {
        /* Not nested after all: plain text. */
        QByteArray text = body;
        if (text.endsWith('\0')) {
            text.chop(1);
        }
        parts << QString::fromUtf8(text).simplified();
    }
    return parts;
}

QVariantList parseInterfaceList(const QString &output)
{
    static const QRegularExpression line_re(QStringLiteral("^\\s*\\d+\\.\\s+(.+?)\\s*$"));
    QVariantList out;
    for (const QString &line : output.split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QRegularExpressionMatch m = line_re.match(line);
        if (!m.hasMatch()) {
            continue;
        }
        QString name = m.captured(1);
        QString description;
        if (name.endsWith(QLatin1Char(')'))) {
            const int open = name.lastIndexOf(QStringLiteral(" ("));
            if (open > 0) {
                description = name.mid(open + 2, name.size() - open - 3);
                name = name.left(open);
            }
        }
        out << QVariantMap { { QStringLiteral("name"), name },
                             { QStringLiteral("description"), description },
                             { QStringLiteral("label"), description.isEmpty() ? name : description } };
    }
    return out;
}

} // namespace SyncPipe
