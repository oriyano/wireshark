/* captureengine.cpp
 *
 * Kitsune - the GUI's handle on the dissection engine.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "captureengine.h"
#include "engineworker.h"

#include <QElapsedTimer>
#include <QEventLoop>
#include <QFileInfo>
#include <QLocale>
#include <QMetaObject>

#include <glib.h>

#include <app/application_flavor.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/prefs.h>
#include <epan/timestamp.h>
#include <epan/cfile.h>
#include <ui/failure_message.h>
#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/version_info.h>
#include <wsutil/wslog.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif

/* Some routines in the ui library refer to the global capture file. */
capture_file cfile;

static bool libraries_ready = false;

bool CaptureEngine::initLibraries(const char *argv0)
{
    if (libraries_ready) {
        return true;
    }

    g_set_prgname("kitsune");
    ws_log_init(NULL, "Kitsune Debug Console");
    init_process_policies();
    relinquish_special_privs_perm();

    char *config_error = configuration_init(argv0, "wireshark");
    if (config_error) {
        ws_warning("Can't get pathname of Kitsune: %s", config_error);
        g_free(config_error);
    }

    ws_init_version_info("Kitsune", NULL, application_get_vcs_version_info,
                         epan_gather_compile_info, epan_gather_runtime_info);
    init_report_failure_message("Kitsune");

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    const struct file_extension_info *file_extensions;
    unsigned num_extensions;
    application_file_extensions(&file_extensions, &num_extensions);
    wtap_init(true, application_configuration_environment_prefix(), file_extensions, num_extensions);

    epan_app_data_t app_data;
    memset(&app_data, 0, sizeof(app_data));
    app_data.env_var_prefix = application_configuration_environment_prefix();
    app_data.col_fmt = application_columns();
    app_data.num_cols = application_num_columns();
    app_data.register_func = register_all_protocols;
    app_data.handoff_func = register_all_protocol_handoffs;
    if (!epan_init(NULL, NULL, true, &app_data)) {
        return false;
    }

    e_prefs *prefs_p = epan_load_settings();
    cap_file_init(&cfile);
    prefs_apply_all();
    build_column_format_array(&cfile.cinfo, prefs_p->num_cols, true);

    libraries_ready = true;
    return true;
}

void CaptureEngine::cleanupLibraries()
{
    if (!libraries_ready) {
        return;
    }
    col_cleanup(&cfile.cinfo);
    epan_cleanup();
    wtap_cleanup();
    free_progdirs();
    libraries_ready = false;
}

CaptureEngine::CaptureEngine(QObject *parent) :
    QObject(parent),
    worker_(new EngineWorker)
{
    qRegisterMetaType<PacketRow>();
    qRegisterMetaType<QVector<PacketRow>>();
    qRegisterMetaType<PacketDetails>();
    qRegisterMetaType<HostInventorySnapshot>();
    qRegisterMetaType<QVector<quint32>>();

    thread_.setObjectName(QStringLiteral("Kitsune engine"));
    worker_->moveToThread(&thread_);
    connect(&thread_, &QThread::finished, worker_, &QObject::deleteLater);

    connect(worker_, &EngineWorker::opened, this, &CaptureEngine::onOpened);
    connect(worker_, &EngineWorker::openFailed, this, &CaptureEngine::onOpenFailed);
    connect(worker_, &EngineWorker::loadProgress, this, &CaptureEngine::onLoadProgress);
    connect(worker_, &EngineWorker::loaded, this, &CaptureEngine::onLoaded);
    connect(worker_, &EngineWorker::inventoryReady, this, &CaptureEngine::onInventoryReady);
    connect(worker_, &EngineWorker::rowsReady, this, &CaptureEngine::onRowsReady);
    connect(worker_, &EngineWorker::detailsReady, this, &CaptureEngine::onDetailsReady);
    connect(worker_, &EngineWorker::filterChecked, this, &CaptureEngine::onFilterChecked);
    connect(worker_, &EngineWorker::filterProgress, this, &CaptureEngine::onFilterProgress);
    connect(worker_, &EngineWorker::filterApplied, this, &CaptureEngine::onFilterApplied);
    connect(worker_, &EngineWorker::filterFailed, this, &CaptureEngine::onFilterFailed);
    connect(worker_, &EngineWorker::liveProgress, this, &CaptureEngine::onLiveProgress);
    connect(this, &CaptureEngine::displayedFramesChanged, this, &CaptureEngine::displayedCountChanged);

    thread_.start();
}

CaptureEngine::~CaptureEngine()
{
    worker_->cancel = true;
    QMetaObject::invokeMethod(worker_, "closeFile", Qt::BlockingQueuedConnection);
    thread_.quit();
    thread_.wait();
}

QString CaptureEngine::fileName() const
{
    return QFileInfo(file_path_).fileName();
}

QString CaptureEngine::formatCount(qint64 value) const
{
    return QLocale().toString(value);
}

int CaptureEngine::columnCount() const
{
    return static_cast<int>(cfile.cinfo.num_cols);
}

QString CaptureEngine::columnTitle(int column) const
{
    if (column < 0 || column >= columnCount()) {
        return QString();
    }
    return QString::fromUtf8(get_column_title(column));
}

void CaptureEngine::setLargeFileMode(bool on)
{
    if (on == large_file_mode_) {
        return;
    }
    large_file_mode_ = on;
    QMetaObject::invokeMethod(worker_, "setLargeFileMode", Qt::QueuedConnection, Q_ARG(bool, on));
    emit largeFileModeChanged();
    /* The setting changes how the first pass dissects, so reload. */
    if (hasFile()) {
        const QString path = file_path_;
        openPath(path);
    }
}

bool CaptureEngine::openFile(const QUrl &url)
{
    return openPath(url.isLocalFile() ? url.toLocalFile() : url.toString());
}

bool CaptureEngine::openPath(const QString &path)
{
    closeFile();
    file_generation_++;
    file_path_ = path;
    loading_ = true;
    load_progress_ = 0.0;
    last_error_.clear();
    emit fileChanged();
    emit loadingChanged();
    emit loadProgressChanged();
    QMetaObject::invokeMethod(worker_, "openFile", Qt::QueuedConnection, Q_ARG(QString, path), Q_ARG(int, file_generation_));
    return true;
}

void CaptureEngine::startLive(const QString &path)
{
    closeFile();
    file_generation_++;
    file_path_ = path;
    live_ = true;
    last_error_.clear();
    emit fileChanged();
    emit liveChanged();
    QMetaObject::invokeMethod(worker_, "openLive", Qt::QueuedConnection, Q_ARG(QString, path), Q_ARG(int, file_generation_));
}

void CaptureEngine::continueLive(int new_packets)
{
    if (!live_) {
        return;
    }
    QMetaObject::invokeMethod(worker_, "continueLive", Qt::QueuedConnection,
                              Q_ARG(int, new_packets), Q_ARG(int, file_generation_));
}

void CaptureEngine::finishLive()
{
    if (!live_) {
        return;
    }
    loading_ = true;    /* until the engine has read the rest and tidied up */
    emit loadingChanged();
    QMetaObject::invokeMethod(worker_, "finishLive", Qt::QueuedConnection, Q_ARG(int, file_generation_));
}

void CaptureEngine::onLiveProgress(int packets, const QVector<quint32> &new_displayed, const QString &duration, int generation)
{
    if (generation != file_generation_) {
        return;
    }
    if (packets != packet_count_) {
        packet_count_ = packets;
        emit packetCountChanged();
    }
    if (duration != duration_) {
        duration_ = duration;
        emit loaded();      /* duration is notified with loaded */
    }
    if (!new_displayed.isEmpty() && !filtering_) {
        const int first = static_cast<int>(displayed_.size());
        displayed_ += new_displayed;
        emit displayedFramesAppended(first, static_cast<int>(new_displayed.size()));
        emit displayedCountChanged();
    }
}

void CaptureEngine::closeFile()
{
    worker_->cancel = true;
    file_generation_++;
    filter_generation_++;
    QMetaObject::invokeMethod(worker_, "closeFile", Qt::QueuedConnection);

    const bool had_file = !file_path_.isEmpty();
    if (live_) {
        live_ = false;
        emit liveChanged();
    }
    file_path_.clear();
    file_type_name_.clear();
    packet_count_ = 0;
    duration_.clear();
    displayed_.clear();
    filter_text_.clear();
    applied_filter_text_.clear();
    filtering_ = false;
    selected_frame_ = 0;
    inventory_ = HostInventorySnapshot();
    if (loading_) {
        loading_ = false;
        emit loadingChanged();
    }
    if (had_file) {
        emit fileChanged();
        emit packetCountChanged();
        emit displayedFramesChanged();
        emit filterChanged();
        emit selectedFrameChanged();
        emit inventoryChanged();
    }
}

void CaptureEngine::onOpened(const QString &path, const QString &file_type, qint64, int generation)
{
    if (generation != file_generation_ || path != file_path_) {
        return;
    }
    file_type_name_ = file_type;
    emit fileChanged();
}

void CaptureEngine::onOpenFailed(const QString &message, int generation)
{
    if (generation != file_generation_) {
        return;
    }
    file_path_.clear();
    loading_ = false;
    last_error_ = message;
    emit fileChanged();
    emit loadingChanged();
    emit errorOccurred(message);
}

void CaptureEngine::onLoadProgress(double progress, int packets, int generation)
{
    if (generation != file_generation_) {
        return;
    }
    setProgress(progress);
    packet_count_ = packets;
    emit packetCountChanged();
}

void CaptureEngine::onLoaded(int packets, qint64 elapsed_ms, const QString &duration, const QString &error, int generation)
{
    if (generation != file_generation_) {
        return;
    }
    packet_count_ = packets;
    load_time_ms_ = elapsed_ms;
    duration_ = duration;
    loading_ = false;
    setProgress(1.0);

    const bool was_live = live_;
    if (live_) {
        live_ = false;
        emit liveChanged();
    }
    /* A live capture kept its displayed list (and filter) up to date. */
    if (!was_live || filter_text_.isEmpty()) {
        displayed_.clear();
        displayed_.reserve(packets);
        for (int frame = 1; frame <= packets; frame++) {
            displayed_.append(static_cast<quint32>(frame));
        }
        filter_time_ms_ = 0;
    }

    emit packetCountChanged();
    emit loadingChanged();
    emit displayedFramesChanged();
    emit loaded();

    if (!error.isEmpty()) {
        last_error_ = tr("The file was only partly read: %1").arg(error);
        emit errorOccurred(last_error_);
    }
}

void CaptureEngine::onInventoryReady(const HostInventorySnapshot &snapshot, int generation)
{
    if (generation != file_generation_) {
        return;
    }
    inventory_ = snapshot;
    emit inventoryChanged();
}

void CaptureEngine::requestRows(const QVector<quint32> &frames)
{
    QMetaObject::invokeMethod(worker_, "requestRows", Qt::QueuedConnection,
                              Q_ARG(QVector<quint32>, frames), Q_ARG(int, file_generation_));
}

QStringList CaptureEngine::columnsBlocking(quint32 frame)
{
    QStringList columns;
    QMetaObject::invokeMethod(worker_, [this, frame, &columns]() {
        columns = worker_->columnsNow(frame);
    }, Qt::BlockingQueuedConnection);
    return columns;
}

void CaptureEngine::onRowsReady(const QVector<PacketRow> &rows, int generation)
{
    if (generation == file_generation_) {
        emit rowsReady(rows);
    }
}

void CaptureEngine::selectFrame(int frame)
{
    if (frame == selected_frame_) {
        return;
    }
    selected_frame_ = frame;
    emit selectedFrameChanged();
    details_generation_++;
    if (frame > 0) {
        QMetaObject::invokeMethod(worker_, "requestDetails", Qt::QueuedConnection,
                                  Q_ARG(quint32, static_cast<quint32>(frame)), Q_ARG(int, details_generation_));
    } else {
        emit detailsReady(PacketDetails());
    }
}

void CaptureEngine::onDetailsReady(const PacketDetails &details, int generation)
{
    if (generation == details_generation_) {
        emit detailsReady(details);
    }
}

void CaptureEngine::checkFilter(const QString &text)
{
    check_generation_++;
    QMetaObject::invokeMethod(worker_, "checkFilter", Qt::QueuedConnection,
                              Q_ARG(QString, text), Q_ARG(int, check_generation_));
}

void CaptureEngine::onFilterChecked(const QString &text, bool valid, const QString &message, int start, int length, int generation)
{
    if (generation == check_generation_) {
        emit filterChecked(text, valid, message, start, length);
    }
}

void CaptureEngine::applyFilter(const QString &text)
{
    if (!hasFile() || loading_) {
        return;
    }
    worker_->cancel = true;   /* stop a filter that is still running */
    filter_generation_++;
    filter_text_ = text.trimmed();
    filtering_ = true;
    filter_progress_ = 0.0;
    emit filterChanged();
    emit filterProgressChanged();
    QMetaObject::invokeMethod(worker_, "applyFilter", Qt::QueuedConnection,
                              Q_ARG(QString, filter_text_), Q_ARG(int, filter_generation_));
}

void CaptureEngine::applyFilterBlocking(const QString &text)
{
    QEventLoop loop;
    auto connection = connect(this, &CaptureEngine::filterChanged, &loop, [this, &loop]() {
        if (!filtering_) loop.quit();
    });
    applyFilter(text);
    if (filtering_) {
        loop.exec();
    }
    disconnect(connection);
}

void CaptureEngine::cancelFilter()
{
    if (!filtering_) {
        return;
    }
    worker_->cancel = true;
    filter_generation_++;
    filtering_ = false;
    filter_text_ = applied_filter_text_;   /* the list still shows the old filter's packets */
    emit filterChanged();
}

void CaptureEngine::onFilterProgress(double progress)
{
    filter_progress_ = progress;
    emit filterProgressChanged();
}

void CaptureEngine::onFilterApplied(const QString &, const QVector<quint32> &frames, qint64 elapsed_ms, int generation)
{
    if (generation != filter_generation_) {
        return;
    }
    displayed_ = frames;
    applied_filter_text_ = filter_text_;
    filter_time_ms_ = elapsed_ms;
    filtering_ = false;
    emit displayedFramesChanged();
    emit filterChanged();
}

void CaptureEngine::onFilterFailed(const QString &, const QString &message, int generation)
{
    if (generation != filter_generation_) {
        return;
    }
    filtering_ = false;
    filter_text_ = applied_filter_text_;
    emit filterChanged();
    last_error_ = message;
    emit errorOccurred(message);
}

void CaptureEngine::setProgress(double progress)
{
    progress = qBound(0.0, progress, 1.0);
    if (qFuzzyCompare(progress + 1.0, load_progress_ + 1.0)) {
        return;
    }
    load_progress_ = progress;
    emit loadProgressChanged();
}

qint64 CaptureEngine::peakMemoryBytes()
{
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) {
        return static_cast<qint64>(counters.PeakWorkingSetSize);
    }
    return 0;
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
#ifdef __APPLE__
        return static_cast<qint64>(usage.ru_maxrss);
#else
        return static_cast<qint64>(usage.ru_maxrss) * 1024;
#endif
    }
    return 0;
#endif
}
