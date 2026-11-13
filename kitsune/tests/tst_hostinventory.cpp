/* tst_hostinventory.cpp
 *
 * Kitsune - unit tests for the host inventory's packet triage and its
 * operating system reasoning. These need no capture file and no
 * dissection engine.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QtTest>

#include <wiretap/wtap.h>

#include "engine/hostinventory.h"

class TestHostInventory : public QObject
{
    Q_OBJECT

private:
    /* Ethernet + IPv4 + TCP, with optional options and payload. */
    static QByteArray tcpPacket(quint8 ttl, quint16 sport, quint16 dport, quint8 flags, quint16 window,
                                const QByteArray &options = QByteArray(), const QByteArray &payload = QByteArray())
    {
        QByteArray p(14, '\0');
        p[12] = 0x08; p[13] = 0x00;
        const int tcp_len = 20 + options.size();
        const int total = 20 + tcp_len + payload.size();
        QByteArray ip(20, '\0');
        ip[0] = 0x45;
        ip[2] = static_cast<char>(total >> 8); ip[3] = static_cast<char>(total & 0xff);
        ip[8] = static_cast<char>(ttl);
        ip[9] = 6;
        QByteArray tcp(20, '\0');
        tcp[0] = static_cast<char>(sport >> 8); tcp[1] = static_cast<char>(sport & 0xff);
        tcp[2] = static_cast<char>(dport >> 8); tcp[3] = static_cast<char>(dport & 0xff);
        tcp[12] = static_cast<char>((tcp_len / 4) << 4);
        tcp[13] = static_cast<char>(flags);
        tcp[14] = static_cast<char>(window >> 8); tcp[15] = static_cast<char>(window & 0xff);
        return p + ip + tcp + options + payload;
    }

    static QByteArray udpPacket(quint16 sport, quint16 dport, const QByteArray &payload)
    {
        QByteArray p(14, '\0');
        p[12] = 0x08; p[13] = 0x00;
        const int total = 20 + 8 + payload.size();
        QByteArray ip(20, '\0');
        ip[0] = 0x45;
        ip[2] = static_cast<char>(total >> 8); ip[3] = static_cast<char>(total & 0xff);
        ip[8] = 64;
        ip[9] = 17;
        QByteArray udp(8, '\0');
        udp[0] = static_cast<char>(sport >> 8); udp[1] = static_cast<char>(sport & 0xff);
        udp[2] = static_cast<char>(dport >> 8); udp[3] = static_cast<char>(dport & 0xff);
        return p + ip + udp + payload;
    }

    static HostInventory::Peek peek(const QByteArray &packet)
    {
        return HostInventory::peek(WTAP_ENCAP_ETHERNET, reinterpret_cast<const uint8_t *>(packet.constData()),
                                   static_cast<unsigned>(packet.size()));
    }

private slots:
    void synIsParsedWithoutATree()
    {
        /* MSS 1460, NOP, window scale 8, NOP, NOP, SACK permitted */
        const QByteArray options = QByteArray::fromHex("020405b401030308010104020000000000000000").left(12);
        const HostInventory::Peek p = peek(tcpPacket(128, 50000, 443, 0x02, 64240, options));
        QVERIFY(p.tcpParsed);
        QVERIFY(!p.needsTree);
        QCOMPARE(p.ttl, 128);
        QCOMPARE(p.window, 64240);
        QCOMPARE(p.mss, 1460);
        QCOMPARE(p.wscale, 8);
        QVERIFY(!p.timestamps);
        QCOMPARE(p.tcpPayload, 0);
    }

    void timestampOptionIsSeen()
    {
        const QByteArray options = QByteArray::fromHex("020405b40402080a0000000100000000");
        const HostInventory::Peek p = peek(tcpPacket(64, 40000, 22, 0x02, 64240, options));
        QVERIFY(p.timestamps);
        QCOMPARE(p.mss, 1460);
    }

    void plainTrafficSkipsTheTree()
    {
        QVERIFY(!peek(tcpPacket(64, 443, 50000, 0x10, 501, QByteArray(), QByteArray(100, 'x'))).needsTree);
        QVERIFY(!peek(tcpPacket(64, 80, 50000, 0x10, 501)).needsTree);   /* bare ACK on a web port */
    }

    void bannersAndHeadersGetATree()
    {
        QVERIFY(peek(tcpPacket(64, 50000, 8081, 0x18, 501, QByteArray(), "GET / HTTP/1.1\r\n")).needsTree);
        QVERIFY(peek(tcpPacket(64, 8081, 50000, 0x18, 501, QByteArray(), "HTTP/1.1 200 OK\r\n")).needsTree);
        QVERIFY(peek(tcpPacket(64, 2222, 50000, 0x18, 501, QByteArray(), "SSH-2.0-OpenSSH_9.6\r\n")).needsTree);
        QVERIFY(peek(tcpPacket(128, 50000, 445, 0x18, 501, QByteArray(), QByteArray(64, '\0'))).needsTree);
    }

    void dnsResponsesOnly()
    {
        QByteArray query(12, '\0');
        QByteArray response(12, '\0');
        response[2] = static_cast<char>(0x81);
        QVERIFY(!peek(udpPacket(50000, 53, query)).needsTree);
        QVERIFY(peek(udpPacket(53, 50000, response)).needsTree);
        QVERIFY(peek(udpPacket(68, 67, QByteArray(240, '\0'))).needsTree);
    }

    void unknownLinkTypesGetATree()
    {
        const QByteArray arp = QByteArray::fromHex("ffffffffffff001a2b000001" "0806") + QByteArray(28, '\0');
        QVERIFY(peek(arp).needsTree);
        const QByteArray packet = tcpPacket(64, 1, 2, 0x10, 1);
        QVERIFY(HostInventory::peek(WTAP_ENCAP_RAW_IP, reinterpret_cast<const uint8_t *>(packet.constData()),
                                    static_cast<unsigned>(packet.size())).needsTree);
    }

    void truncatedPacketsAreSafe()
    {
        const QByteArray packet = tcpPacket(64, 1, 2, 0x02, 1, QByteArray::fromHex("020405b4"));
        for (int len = 0; len < packet.size(); len++) {
            HostInventory::peek(WTAP_ENCAP_ETHERNET, reinterpret_cast<const uint8_t *>(packet.constData()),
                                static_cast<unsigned>(len));
        }
        /* Options that claim to run past the header. */
        const HostInventory::Peek p = peek(tcpPacket(64, 1, 2, 0x02, 1, QByteArray::fromHex("02ff05b4")));
        QCOMPARE(p.mss, -1);
    }

    void handshakeFingerprints_data()
    {
        QTest::addColumn<int>("ttl");
        QTest::addColumn<int>("window");
        QTest::addColumn<int>("wscale");
        QTest::addColumn<bool>("timestamps");
        QTest::addColumn<QString>("family");
        QTest::addColumn<QString>("os");
        QTest::newRow("windows") << 128 << 64240 << 8 << false << "Windows" << "Windows 10/11";
        QTest::newRow("windows hops") << 121 << 64240 << 8 << false << "Windows" << "Windows 10/11";
        QTest::newRow("linux") << 64 << 64240 << 7 << true << "Linux" << "Linux";
        QTest::newRow("mac") << 64 << 65535 << 6 << true << "macOS" << "macOS / iOS";
        QTest::newRow("embedded") << 255 << 5840 << -1 << false << "Embedded" << "Network device / embedded";
    }

    void handshakeFingerprints()
    {
        QFETCH(int, ttl);
        QFETCH(int, window);
        QFETCH(int, wscale);
        QFETCH(bool, timestamps);
        QFETCH(QString, family);
        QFETCH(QString, os);
        const QVector<OsEvidence> e = HostInventory::tcpEvidence(ttl, window, 1460, wscale, timestamps, 1);
        QCOMPARE(e.size(), 1);
        QCOMPARE(e.first().family, family);
        QCOMPARE(e.first().os, os);
    }

    void bannerEvidence()
    {
        QCOMPARE(HostInventory::sshBannerEvidence(QStringLiteral("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"), 1).value(0).os,
                 QStringLiteral("Ubuntu 24.04"));
        QCOMPARE(HostInventory::userAgentEvidence(QStringLiteral("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), 1).value(0).family,
                 QStringLiteral("Windows"));
        QCOMPARE(HostInventory::serverHeaderEvidence(QStringLiteral("Microsoft-IIS/10.0"), 1).value(0).os,
                 QStringLiteral("Windows Server 2016 or later"));
    }

    void appEvidenceOutweighsHandshake()
    {
        HostRecord host;
        host.osEvidence << HostInventory::tcpEvidence(64, 64240, 1460, 7, true, 1)
                        << HostInventory::sshBannerEvidence(QStringLiteral("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"), 2);
        HostInventory::chooseOs(host);
        QCOMPARE(host.osFamily, QStringLiteral("Linux"));
        QCOMPARE(host.os, QStringLiteral("Ubuntu 24.04"));
        QCOMPARE(host.osConfidence, 3);
    }

    void conflictingEvidenceLowersConfidence()
    {
        HostRecord host;
        host.osEvidence << HostInventory::tcpEvidence(128, 64240, 1460, 8, false, 1)
                        << HostInventory::tcpEvidence(64, 64240, 1460, 7, true, 2);
        HostInventory::chooseOs(host);
        QVERIFY(host.osConfidence <= 1);
    }

    void noEvidenceMeansUnknown()
    {
        HostRecord host;
        HostInventory::chooseOs(host);
        QVERIFY(host.os.isEmpty());
        QCOMPARE(host.osConfidence, 0);
    }

    void subnets()
    {
        QCOMPARE(HostInventory::subnetFor(QStringLiteral("192.168.20.12")), QStringLiteral("192.168.20.0/24"));
        QCOMPARE(HostInventory::subnetFor(QStringLiteral("8.8.8.8")), QStringLiteral("Internet"));
        QVERIFY(HostInventory::isPrivateIpv4(QStringLiteral("172.20.1.1")));
        QVERIFY(!HostInventory::isPrivateIpv4(QStringLiteral("172.32.1.1")));
    }
};

QTEST_GUILESS_MAIN(TestHostInventory)
#include "tst_hostinventory.moc"
