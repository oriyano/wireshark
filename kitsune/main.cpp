/* main.cpp
 *
 * Kitsune - a QML interface on top of the Wireshark engine,
 * designed for training and education.
 *
 * Usage:
 *   kitsune [capture-file]
 *   kitsune --bench capture-file   Load the file, read every row of the
 *                                  packet list and print timings.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QCommandLineParser>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QTextStream>
#include <QTimer>

#include <cstdio>

#include "engine/captureengine.h"
#include "engine/kitsunesettings.h"
#include "models/hostmodels.h"
#include "models/packetdetailsmodel.h"
#include "models/packetlistmodel.h"

static int runBenchmark(const QString &path, const QString &filter)
{
    QTextStream out(stdout);
    CaptureEngine engine;
    PacketListModel model(&engine);
    model.setSynchronous(true);

    QElapsedTimer total;
    total.start();

    QEventLoop loop;
    QObject::connect(&engine, &CaptureEngine::loaded, &loop, &QEventLoop::quit);
    if (!engine.openPath(path)) {
        out << "error: " << engine.lastError() << Qt::endl;
        return 1;
    }
    loop.exec();

    const qint64 first_pass_ms = engine.loadTimeMs();
    const qint64 mem_after_load = CaptureEngine::peakMemoryBytes();

    /* Time to first screen: the rows a view shows right after opening. */
    QElapsedTimer screen;
    screen.start();
    const int visible_rows = qMin(model.rowCount(), 50);
    for (int row = 0; row < visible_rows; row++) {
        for (int col = 0; col < model.columnCount(); col++) {
            model.data(model.index(row, col));
        }
    }
    const qint64 first_screen_ms = screen.elapsed();

    /* Scroll through the whole capture, reading every cell once. */
    QElapsedTimer scroll;
    scroll.start();
    for (int row = 0; row < model.rowCount(); row++) {
        for (int col = 0; col < model.columnCount(); col++) {
            model.data(model.index(row, col));
        }
    }
    const qint64 scroll_ms = scroll.elapsed();
    const double per_row_us = model.rowCount() > 0 ?
        static_cast<double>(scroll_ms) * 1000.0 / model.rowCount() : 0.0;

    /* Display filter over the whole capture. */
    qint64 filter_ms = -1;
    if (!filter.isEmpty()) {
        engine.applyFilterBlocking(filter);
        filter_ms = engine.filterTimeMs();
    }

    out << "file:               " << engine.fileName() << " (" << engine.fileTypeName() << ")" << Qt::endl;
    out << "packets:            " << engine.packetCount() << Qt::endl;
    out << "first pass:         " << first_pass_ms << " ms" << Qt::endl;
    out << "first screen:       " << first_screen_ms << " ms (" << visible_rows << " rows)" << Qt::endl;
    out << "full scroll:        " << scroll_ms << " ms (" << QString::number(per_row_us, 'f', 1) << " us/row)" << Qt::endl;
    if (filter_ms >= 0) {
        out << "filter:             \"" << filter << "\" matched " << engine.displayedCount()
            << " in " << filter_ms << " ms" << Qt::endl;
    }
    out << "hosts found:        " << engine.inventory().hosts.size() << " in "
        << engine.inventory().subnets.size() << " subnets" << Qt::endl;
    out << "total:              " << total.elapsed() << " ms" << Qt::endl;
    out << "peak memory, load:  " << mem_after_load / (1024 * 1024) << " MiB" << Qt::endl;
    out << "peak memory, end:   " << CaptureEngine::peakMemoryBytes() / (1024 * 1024) << " MiB" << Qt::endl;
    return 0;
}

/* Print the host inventory, for checking discovery from the command line. */
static int runInventory(const QString &path)
{
    QTextStream out(stdout);
    CaptureEngine engine;
    QEventLoop loop;
    QObject::connect(&engine, &CaptureEngine::loaded, &loop, &QEventLoop::quit);
    QObject::connect(&engine, &CaptureEngine::errorOccurred, &loop, &QEventLoop::quit);
    engine.openPath(path);
    loop.exec();

    static const char *confidence[] = { "unknown", "low", "medium", "high" };
    const HostInventorySnapshot &inv = engine.inventory();
    for (const SubnetRecord &subnet : inv.subnets) {
        out << subnet.cidr << "  " << subnet.hostCount << " hosts";
        if (!subnet.suggestedName.isEmpty()) out << "  (looks like: " << subnet.suggestedName << ")";
        out << Qt::endl;
        for (const HostRecord &h : inv.hosts) {
            if (h.subnet != subnet.cidr) continue;
            out << "  " << (h.ipv4.isEmpty() ? h.ipv6.value(0) : h.ipv4) << "  " << (h.name.isEmpty() ? "-" : h.name)
                << "  " << (h.mac.isEmpty() ? "-" : h.mac) << (h.isRouter ? "  [router]" : "")
                << "  OS: " << (h.os.isEmpty() ? "?" : h.os) << " (" << confidence[h.osConfidence] << ")" << Qt::endl;
            for (const ServiceRecord &svc : h.services) {
                out << "      " << svc.transport << "/" << svc.port << " " << svc.service;
                if (!svc.banner.isEmpty()) out << "  \"" << svc.banner << "\"";
                out << Qt::endl;
            }
            for (const OsEvidence &e : h.osEvidence) {
                out << "      evidence: " << e.source << " -> " << e.os << " (" << e.detail << ", frame " << e.frame << ")" << Qt::endl;
            }
        }
    }
    return engine.inventory().hosts.isEmpty() ? 1 : 0;
}

int main(int argc, char *argv[])
{
    QGuiApplication::setApplicationName(QStringLiteral("Kitsune"));
    QGuiApplication::setOrganizationName(QStringLiteral("Kitsune"));
    QGuiApplication app(argc, argv);

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Kitsune network analyzer"));
    parser.addHelpOption();
    QCommandLineOption bench_option(QStringLiteral("bench"),
                                    QStringLiteral("Load a capture, read every packet list row and print timings."));
    parser.addOption(bench_option);
    QCommandLineOption filter_option(QStringLiteral("filter"),
                                     QStringLiteral("With --bench, also time this display filter."),
                                     QStringLiteral("expression"));
    parser.addOption(filter_option);
    QCommandLineOption inventory_option(QStringLiteral("inventory"),
                                        QStringLiteral("Print the hosts, services and OS guesses found in a capture."));
    parser.addOption(inventory_option);
    QCommandLineOption screenshot_option(QStringLiteral("screenshot"),
                                         QStringLiteral("Save a screenshot of the main window to <file> and exit."),
                                         QStringLiteral("file"));
    parser.addOption(screenshot_option);
    QCommandLineOption view_option(QStringLiteral("view"),
                                   QStringLiteral("Start on <view>: packets or map."), QStringLiteral("view"));
    parser.addOption(view_option);
    QCommandLineOption select_option(QStringLiteral("select"),
                                     QStringLiteral("Select packet <number> once the file loads."), QStringLiteral("number"));
    parser.addOption(select_option);
    QCommandLineOption apply_filter_option(QStringLiteral("display-filter"),
                                           QStringLiteral("Apply <filter> once the file loads."), QStringLiteral("filter"));
    parser.addOption(apply_filter_option);
    QCommandLineOption draft_filter_option(QStringLiteral("filter-draft"),
                                           QStringLiteral("Type <filter> into the filter bar without applying it."), QStringLiteral("filter"));
    parser.addOption(draft_filter_option);
    QCommandLineOption details_row_option(QStringLiteral("details-row"),
                                          QStringLiteral("Select row <row> of the packet details tree."), QStringLiteral("row"));
    parser.addOption(details_row_option);
    QCommandLineOption subnet_option(QStringLiteral("subnet"),
                                     QStringLiteral("In the network view, open <cidr>."), QStringLiteral("cidr"));
    parser.addOption(subnet_option);
    QCommandLineOption host_option(QStringLiteral("host"),
                                   QStringLiteral("In the network view, open the host at <row>."), QStringLiteral("row"));
    parser.addOption(host_option);
    QCommandLineOption theme_option(QStringLiteral("theme"),
                                    QStringLiteral("Use <mode> for this run: system, light or dark."),
                                    QStringLiteral("mode"));
    parser.addOption(theme_option);
    parser.addPositionalArgument(QStringLiteral("file"), QStringLiteral("Capture file to open."));
    parser.process(app);

    if (!CaptureEngine::initLibraries(argv[0])) {
        std::fprintf(stderr, "kitsune: could not initialize the dissection engine\n");
        return 2;
    }

    const QStringList files = parser.positionalArguments();
    if (parser.isSet(bench_option)) {
        if (files.isEmpty()) {
            std::fprintf(stderr, "kitsune: --bench needs a capture file\n");
            return 1;
        }
        int ret = runBenchmark(files.first(), parser.value(filter_option));
        CaptureEngine::cleanupLibraries();
        return ret;
    }

    if (parser.isSet(inventory_option)) {
        if (files.isEmpty()) {
            std::fprintf(stderr, "kitsune: --inventory needs a capture file\n");
            return 1;
        }
        int ret = runInventory(files.first());
        CaptureEngine::cleanupLibraries();
        return ret;
    }

    QQuickStyle::setStyle(QStringLiteral("Basic"));

    int ret;
    {
        CaptureEngine engine;
        PacketListModel packet_list(&engine);
        PacketDetailsModel packet_details(&engine);
        PacketBytesModel packet_bytes(&packet_details);
        SubnetListModel subnets(&engine);
        HostListModel hosts(&engine);
        HostListModel subnet_hosts(&engine);
        KitsuneSettings settings;

        if (parser.isSet(theme_option)) {
            const QString mode = parser.value(theme_option);
            settings.setThemeModeForSession(mode == QLatin1String("light") ? 1 : mode == QLatin1String("system") ? 0 : 2);
        }

        QQmlApplicationEngine qml;
        qml.rootContext()->setContextProperty(QStringLiteral("captureEngine"), &engine);
        qml.rootContext()->setContextProperty(QStringLiteral("packetListModel"), &packet_list);
        qml.rootContext()->setContextProperty(QStringLiteral("packetDetailsModel"), &packet_details);
        qml.rootContext()->setContextProperty(QStringLiteral("packetBytesModel"), &packet_bytes);
        qml.rootContext()->setContextProperty(QStringLiteral("subnetModel"), &subnets);
        qml.rootContext()->setContextProperty(QStringLiteral("hostModel"), &hosts);
        qml.rootContext()->setContextProperty(QStringLiteral("subnetHostModel"), &subnet_hosts);
        qml.rootContext()->setContextProperty(QStringLiteral("kitsuneSettings"), &settings);
        QObject::connect(&qml, &QQmlApplicationEngine::objectCreationFailed,
                         &app, []() { QCoreApplication::exit(-1); }, Qt::QueuedConnection);
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
        qml.loadFromModule(QStringLiteral("Kitsune"), QStringLiteral("Main"));
#else
        qml.addImportPath(QStringLiteral("qrc:/qt/qml"));
        qml.load(QUrl(QStringLiteral("qrc:/qt/qml/Kitsune/Main.qml")));
#endif
        if (qml.rootObjects().isEmpty()) {
            return -1;
        }

        if (parser.isSet(view_option)) {
            qml.rootObjects().first()->setProperty("currentView", parser.value(view_option));
        }
        if (parser.isSet(draft_filter_option)) {
            /* After any --display-filter has run, so it isn't overwritten. */
            QObject *root = qml.rootObjects().first();
            const QString draft = parser.value(draft_filter_option);
            QObject::connect(&engine, &CaptureEngine::loaded, root, [root, draft]() {
                QTimer::singleShot(400, root, [root, draft]() { root->setProperty("filterDraft", draft); });
            });
        }
        if (parser.isSet(details_row_option)) {
            QObject *root = qml.rootObjects().first();
            const int row = parser.value(details_row_option).toInt();
            QObject::connect(&engine, &CaptureEngine::detailsReady, root, [root, row]() {
                root->setProperty("detailsRow", -1);
                root->setProperty("detailsRow", row);
            });
        }
        if (parser.isSet(subnet_option)) {
            qml.rootObjects().first()->setProperty("mapSubnet", parser.value(subnet_option));
        }
        if (parser.isSet(host_option)) {
            qml.rootObjects().first()->setProperty("mapHostRow", parser.value(host_option).toInt());
        }
        if (!files.isEmpty()) {
            const int select = parser.value(select_option).toInt();
            const QString filter = parser.value(apply_filter_option);
            QObject::connect(&engine, &CaptureEngine::loaded, &engine, [&engine, select, filter]() {
                if (!filter.isEmpty()) engine.applyFilter(filter);
                if (select > 0) engine.selectFrame(select);
            });
            engine.openPath(files.first());
        }

        if (parser.isSet(screenshot_option)) {
            const QString shot_path = parser.value(screenshot_option);
            QObject *root = qml.rootObjects().first();
            auto take_shot = [root, shot_path]() {
                if (auto *window = qobject_cast<QQuickWindow *>(root)) {
                    window->grabWindow().save(shot_path);
                }
                QCoreApplication::quit();
            };
            if (!files.isEmpty()) {
                QObject::connect(&engine, &CaptureEngine::loaded, root, [take_shot]() {
                    QTimer::singleShot(800, take_shot);
                });
            } else {
                QTimer::singleShot(1200, take_shot);
            }
        }

        ret = app.exec();
    }
    CaptureEngine::cleanupLibraries();
    return ret;
}
