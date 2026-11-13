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
#include "models/packetlistmodel.h"

static int runBenchmark(const QString &path)
{
    QTextStream out(stdout);
    CaptureEngine engine;
    PacketListModel model(&engine);

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

    out << "file:               " << engine.fileName() << " (" << engine.fileTypeName() << ")" << Qt::endl;
    out << "packets:            " << engine.packetCount() << Qt::endl;
    out << "first pass:         " << first_pass_ms << " ms" << Qt::endl;
    out << "first screen:       " << first_screen_ms << " ms (" << visible_rows << " rows)" << Qt::endl;
    out << "full scroll:        " << scroll_ms << " ms (" << QString::number(per_row_us, 'f', 1) << " us/row)" << Qt::endl;
    out << "total:              " << total.elapsed() << " ms" << Qt::endl;
    out << "peak memory, load:  " << mem_after_load / (1024 * 1024) << " MiB" << Qt::endl;
    out << "peak memory, end:   " << CaptureEngine::peakMemoryBytes() / (1024 * 1024) << " MiB" << Qt::endl;
    return 0;
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
    QCommandLineOption screenshot_option(QStringLiteral("screenshot"),
                                         QStringLiteral("Save a screenshot of the main window to <file> and exit."),
                                         QStringLiteral("file"));
    parser.addOption(screenshot_option);
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
        int ret = runBenchmark(files.first());
        CaptureEngine::cleanupLibraries();
        return ret;
    }

    QQuickStyle::setStyle(QStringLiteral("Basic"));

    int ret;
    {
        CaptureEngine engine;
        PacketListModel packet_list(&engine);
        KitsuneSettings settings;

        if (parser.isSet(theme_option)) {
            const QString mode = parser.value(theme_option);
            settings.setThemeMode(mode == QLatin1String("light") ? 1 : mode == QLatin1String("system") ? 0 : 2);
        }

        QQmlApplicationEngine qml;
        qml.rootContext()->setContextProperty(QStringLiteral("captureEngine"), &engine);
        qml.rootContext()->setContextProperty(QStringLiteral("packetListModel"), &packet_list);
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

        if (!files.isEmpty()) {
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
