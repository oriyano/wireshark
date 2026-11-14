/* tst_syncpipe.cpp
 *
 * Kitsune - tests for talking to dumpcap. The byte strings are what
 * dumpcap writes on stderr when run with "-Z none".
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QtTest>

#include "capture/syncpipe.h"

using namespace SyncPipe;

static QByteArray message(char type, const QByteArray &body)
{
    QByteArray out;
    out.append(type);
    out.append(static_cast<char>((body.size() >> 16) & 0xff));
    out.append(static_cast<char>((body.size() >> 8) & 0xff));
    out.append(static_cast<char>(body.size() & 0xff));
    out.append(body);
    return out;
}

static QByteArray stringMessage(char type, const QByteArray &text)
{
    return message(type, text + QByteArray(1, '\0'));
}

class TestSyncPipe : public QObject
{
    Q_OBJECT

private slots:
    void parsesFileAndCounts()
    {
        QByteArray buffer = stringMessage(sp_file, "/tmp/kitsune/capture.pcapng")
                          + stringMessage(sp_packet_count, "17")
                          + stringMessage(sp_drops, "2");
        const QVector<Message> messages = parseMessages(buffer);
        QCOMPARE(messages.size(), 3);
        QCOMPARE(messages[0].type, sp_file);
        QCOMPARE(messages[0].body, QByteArray("/tmp/kitsune/capture.pcapng"));
        QCOMPARE(messages[1].body.toInt(), 17);
        QCOMPARE(messages[2].type, sp_drops);
        QVERIFY(buffer.isEmpty());
    }

    void waitsForTheRestOfAMessage()
    {
        const QByteArray whole = stringMessage(sp_packet_count, "1234");
        QByteArray buffer = whole.left(6);
        QVERIFY(parseMessages(buffer).isEmpty());
        QCOMPARE(buffer.size(), 6);
        buffer += whole.mid(6);
        const QVector<Message> messages = parseMessages(buffer);
        QCOMPARE(messages.size(), 1);
        QCOMPARE(messages[0].body, QByteArray("1234"));
    }

    void headerSplitAcrossReads()
    {
        const QByteArray whole = stringMessage(sp_success, QByteArray()) + stringMessage(sp_packet_count, "5");
        QByteArray buffer = whole.left(2);
        QVERIFY(parseMessages(buffer).isEmpty());
        buffer += whole.mid(2);
        QCOMPARE(parseMessages(buffer).size(), 2);
    }

    void errorHoldsTwoMessages()
    {
        /* As dumpcap sends "no such device". */
        const QByteArray inner = stringMessage(sp_error, "There is no device named \"nosuch0\".\n(No such device exists)")
                               + stringMessage(sp_error, "");
        QByteArray buffer = message(sp_error, inner);
        const QVector<Message> messages = parseMessages(buffer);
        QCOMPARE(messages.size(), 1);
        QCOMPARE(messages[0].type, sp_error);
        const QStringList parts = errorText(messages[0].body);
        QCOMPARE(parts, QStringList({ "There is no device named \"nosuch0\". (No such device exists)" }));
    }

    void badFilter()
    {
        QByteArray buffer = stringMessage(sp_bad_filter, "0:can't parse filter expression: syntax error");
        const QVector<Message> messages = parseMessages(buffer);
        QCOMPARE(messages.size(), 1);
        QCOMPARE(messages[0].type, sp_bad_filter);
        QVERIFY(messages[0].body.endsWith("syntax error"));
    }

    void skipsStrayText()
    {
        QByteArray buffer = QByteArray("warning: something\n") + stringMessage(sp_packet_count, "3");
        const QVector<Message> messages = parseMessages(buffer);
        QVERIFY(!messages.isEmpty());
        QCOMPARE(messages.last().type, sp_packet_count);
        QCOMPARE(messages.last().body, QByteArray("3"));
    }

    void interfaceList()
    {
        const QVariantList list = parseInterfaceList(QStringLiteral(
            "1. eth0\n"
            "2. any (Pseudo-device that captures on all interfaces)\n"
            "3. lo (Loopback)\n"
            "4. \\Device\\NPF_{6B5F3A9E-1111-2222-3333-444455556666} (Ethernet)\n"
            "not an interface line\n"));
        QCOMPARE(list.size(), 4);
        QCOMPARE(list[0].toMap().value("name").toString(), QStringLiteral("eth0"));
        QCOMPARE(list[0].toMap().value("label").toString(), QStringLiteral("eth0"));
        QCOMPARE(list[2].toMap().value("name").toString(), QStringLiteral("lo"));
        QCOMPARE(list[2].toMap().value("label").toString(), QStringLiteral("Loopback"));
        QCOMPARE(list[3].toMap().value("name").toString(),
                 QStringLiteral("\\Device\\NPF_{6B5F3A9E-1111-2222-3333-444455556666}"));
        QCOMPARE(list[3].toMap().value("description").toString(), QStringLiteral("Ethernet"));
    }

    void argumentsPlain()
    {
        const QStringList args = captureArguments(QStringLiteral("eth0"), QString(), QStringLiteral("/tmp/out.pcapng"),
                                                  false, 5, 100);
        QCOMPARE(args, QStringList({ "-Z", "none", "-i", "eth0", "-w", "/tmp/out.pcapng" }));
    }

    void argumentsFilterAndRing()
    {
        const QStringList args = captureArguments(QStringLiteral("lo"), QStringLiteral("  tcp port 443 "),
                                                  QStringLiteral("out.pcapng"), true, 10, 250);
        QCOMPARE(args, QStringList({ "-Z", "none", "-i", "lo", "-w", "out.pcapng", "-f", "tcp port 443",
                                     "-b", "files:10", "-b", "filesize:250000" }));
        /* A ring needs at least two files. */
        QVERIFY(captureArguments(QStringLiteral("lo"), QString(), QStringLiteral("o"), true, 1, 1).contains("files:2"));
    }
};

int runSyncPipeTests(int argc, char *argv[])
{
    TestSyncPipe test;
    return QTest::qExec(&test, argc, argv);
}

#include "tst_syncpipe.moc"
