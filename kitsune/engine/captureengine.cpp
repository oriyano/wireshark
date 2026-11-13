/* captureengine.cpp
 *
 * Kitsune - a QML interface on top of the Wireshark engine.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "captureengine.h"

#include <QElapsedTimer>
#include <QFileInfo>
#include <QLocale>
#include <QMetaObject>

#include <glib.h>

#include <app/application_flavor.h>
#include <epan/addr_resolv.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data_sequence.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/secrets.h>
#include <epan/timestamp.h>
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

static epan_t *kitsune_epan_new(capture_file *cf)
{
    static const struct packet_provider_funcs funcs = {
        cap_file_provider_get_frame_ts,
        cap_file_provider_get_start_ts,
        cap_file_provider_get_end_ts,
        cap_file_provider_get_interface_name,
        cap_file_provider_get_interface_description,
        cap_file_provider_get_modified_block,
        cap_file_provider_get_process_id,
        cap_file_provider_get_process_name,
        cap_file_provider_get_process_uuid,
        cap_file_provider_get_process_path,
        cap_file_provider_get_process_cmdline,
        cap_file_provider_get_process_parent_id,
        cap_file_provider_get_process_user_id,
        cap_file_provider_get_process_user_name,
        cap_file_provider_get_process_start_time,
        cap_file_provider_find_process_info,
    };

    return epan_new(&cf->provider, &funcs);
}

CaptureEngine::CaptureEngine(QObject *parent) :
    QObject(parent),
    cf_(&cfile),
    load_thread_(nullptr),
    cancel_load_(false),
    loading_(false),
    load_progress_(0.0),
    packet_count_(0),
    load_time_ms_(0),
    file_size_(0)
{
}

CaptureEngine::~CaptureEngine()
{
    closeFile();
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
    return static_cast<int>(cf_->cinfo.num_cols);
}

QString CaptureEngine::columnTitle(int column) const
{
    if (column < 0 || column >= columnCount()) {
        return QString();
    }
    return QString::fromUtf8(get_column_title(column));
}

bool CaptureEngine::openFile(const QUrl &url)
{
    return openPath(url.isLocalFile() ? url.toLocalFile() : url.toString());
}

bool CaptureEngine::openPath(const QString &path)
{
    closeFile();

    int err = 0;
    char *err_info = nullptr;
    QByteArray native_path = path.toUtf8();
    wtap *wth = wtap_open_offline(native_path.constData(), WTAP_TYPE_AUTO, &err, &err_info, true,
                                  application_configuration_environment_prefix());
    if (!wth) {
        last_error_ = tr("Couldn't open %1: %2").arg(QFileInfo(path).fileName(),
                                                     QString::fromUtf8(wtap_strerror(err)));
        if (err_info) {
            last_error_ += QStringLiteral(" (%1)").arg(QString::fromUtf8(err_info));
            g_free(err_info);
        }
        emit errorOccurred(last_error_);
        return false;
    }

    cf_->provider.wth = wth;
    cf_->filename = g_strdup(native_path.constData());
    cf_->is_tempfile = false;
    cf_->unsaved_changes = false;
    cf_->f_datalen = 0;
    cf_->cd_t = wtap_file_type_subtype(wth);
    cf_->open_type = WTAP_TYPE_AUTO;
    cf_->count = 0;
    cf_->drops_known = false;
    cf_->drops = 0;
    cf_->snap = wtap_snapshot_length(wth);
    nstime_set_zero(&cf_->elapsed_time);
    cf_->provider.ref = nullptr;
    cf_->provider.prev_dis = nullptr;
    cf_->provider.prev_cap = nullptr;
    cf_->cum_bytes = 0;
    cf_->provider.frames = new_frame_data_sequence();
    cf_->epan = kitsune_epan_new(cf_);
    cf_->state = FILE_READ_IN_PROGRESS;

    wtap_set_cb_new_ipv4(wth, add_ipv4_name);
    wtap_set_cb_new_ipv6(wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
    wtap_set_cb_new_secrets(wth, secrets_wtap_callback);

    err = 0;
    file_size_ = wtap_file_size(wth, &err);
    file_type_name_ = QString::fromUtf8(wtap_file_type_subtype_description(cf_->cd_t));
    file_path_ = path;
    last_error_.clear();
    packet_count_ = 0;
    duration_.clear();
    load_time_ms_ = 0;
    emit fileChanged();
    emit packetCountChanged();

    loading_ = true;
    cancel_load_ = false;
    setProgress(0.0);
    emit loadingChanged();

    load_thread_ = QThread::create([this]() { runFirstPass(); });
    load_thread_->start();
    return true;
}

/* Worker thread. Sequential read of the whole file, building the frame
 * table. No GUI-thread code touches epan until onLoadFinished runs. */
void CaptureEngine::runFirstPass()
{
    QElapsedTimer timer;
    timer.start();

    int err = 0;
    char *err_info = nullptr;
    int64_t data_offset = 0;
    wtap_rec rec;
    static frame_data ref_frame;

    /* A tree is only needed if postdissectors ask for fields. */
    epan_dissect_t *edt = epan_dissect_new(cf_->epan, postdissectors_want_hfids(), false);
    wtap_rec_init(&rec, 2048);

    qint64 last_report = 0;
    while (!cancel_load_ && wtap_read(cf_->provider.wth, &rec, &err, &err_info, &data_offset)) {
        frame_data fdlocal;
        frame_data_init(&fdlocal, cf_->count + 1, &rec, data_offset, cf_->cum_bytes);
        frame_data_set_before_dissect(&fdlocal, &cf_->elapsed_time, &cf_->provider.ref, cf_->provider.prev_dis);
        if (cf_->provider.ref == &fdlocal) {
            ref_frame = fdlocal;
            cf_->provider.ref = &ref_frame;
        }

        epan_dissect_run(edt, cf_->cd_t, &rec, &fdlocal, NULL);

        frame_data_set_after_dissect(&fdlocal, &cf_->cum_bytes);
        cf_->provider.prev_cap = cf_->provider.prev_dis =
            frame_data_sequence_add(cf_->provider.frames, &fdlocal);
        cf_->count++;
        epan_dissect_reset(edt);
        wtap_rec_reset(&rec);

        qint64 now = timer.elapsed();
        if (now - last_report >= 100) {
            last_report = now;
            double progress = file_size_ > 0 ?
                static_cast<double>(wtap_read_so_far(cf_->provider.wth)) / static_cast<double>(file_size_) : 0.0;
            int count = static_cast<int>(cf_->count);
            QMetaObject::invokeMethod(this, [this, progress, count]() {
                setProgress(progress);
                packet_count_ = count;
                emit packetCountChanged();
            }, Qt::QueuedConnection);
        }
    }

    epan_dissect_free(edt);
    wtap_rec_cleanup(&rec);
    wtap_sequential_close(cf_->provider.wth);
    postseq_cleanup_all_protocols();
    cf_->provider.prev_dis = nullptr;
    cf_->provider.prev_cap = nullptr;

    QString err_message;
    if (err != 0) {
        err_message = QString::fromUtf8(wtap_strerror(err));
        if (err_info) {
            err_message += QStringLiteral(" (%1)").arg(QString::fromUtf8(err_info));
        }
    }
    g_free(err_info);

    qint64 elapsed = timer.elapsed();
    QMetaObject::invokeMethod(this, "onLoadFinished", Qt::QueuedConnection,
                              Q_ARG(int, err), Q_ARG(QString, err_message), Q_ARG(qint64, elapsed));
}

void CaptureEngine::onLoadFinished(int err, const QString &err_message, qint64 elapsed_ms)
{
    if (load_thread_) {
        load_thread_->wait();
        delete load_thread_;
        load_thread_ = nullptr;
    }

    cf_->state = FILE_READ_DONE;
    packet_count_ = static_cast<int>(cf_->count);
    load_time_ms_ = elapsed_ms;

    if (cf_->count > 0) {
        frame_data *first = frame_data_sequence_find(cf_->provider.frames, 1);
        frame_data *last = frame_data_sequence_find(cf_->provider.frames, cf_->count);
        if (first && last) {
            qint64 secs = last->abs_ts.secs - first->abs_ts.secs;
            if (secs < 0) secs = 0;
            duration_ = QStringLiteral("%1:%2:%3")
                .arg(secs / 3600, 2, 10, QLatin1Char('0'))
                .arg((secs / 60) % 60, 2, 10, QLatin1Char('0'))
                .arg(secs % 60, 2, 10, QLatin1Char('0'));
        }
    }

    loading_ = false;
    setProgress(1.0);
    emit packetCountChanged();
    emit loadingChanged();
    emit loaded();

    if (err != 0) {
        last_error_ = tr("The file was only partly read: %1").arg(err_message);
        emit errorOccurred(last_error_);
    }
}

void CaptureEngine::closeFile()
{
    if (load_thread_) {
        cancel_load_ = true;
        load_thread_->wait();
        delete load_thread_;
        load_thread_ = nullptr;
    }

    if (cf_->provider.wth) {
        wtap_close(cf_->provider.wth);
        cf_->provider.wth = nullptr;
    }
    if (cf_->provider.frames) {
        free_frame_data_sequence(cf_->provider.frames);
        cf_->provider.frames = nullptr;
    }
    if (cf_->epan) {
        epan_free(cf_->epan);
        cf_->epan = nullptr;
    }
    g_free(cf_->filename);
    cf_->filename = nullptr;
    cf_->count = 0;
    cf_->state = FILE_CLOSED;

    bool had_file = !file_path_.isEmpty();
    file_path_.clear();
    packet_count_ = 0;
    duration_.clear();
    if (loading_) {
        loading_ = false;
        emit loadingChanged();
    }
    if (had_file) {
        emit fileChanged();
        emit packetCountChanged();
    }
}

bool CaptureEngine::dissectColumns(uint32_t frame_num, QStringList &columns)
{
    if (loading_ || !cf_->provider.frames || frame_num == 0 || frame_num > cf_->count) {
        return false;
    }

    frame_data *fdata = frame_data_sequence_find(cf_->provider.frames, frame_num);
    if (!fdata) {
        return false;
    }

    column_info *cinfo = &cf_->cinfo;
    wtap_rec rec;
    wtap_rec_init(&rec, 2048);
    int err = 0;
    char *err_info = nullptr;

    if (!wtap_seek_read(cf_->provider.wth, fdata->file_off, &rec, &err, &err_info)) {
        g_free(err_info);
        wtap_rec_cleanup(&rec);
        col_fill_in_error(cinfo, fdata, false, true);
        for (unsigned i = 0; i < cinfo->num_cols; i++) {
            columns << QString::fromUtf8(get_column_text(cinfo, i));
        }
        return true;
    }

    epan_dissect_t edt;
    epan_dissect_init(&edt, cf_->epan, have_custom_cols(cinfo), false);
    col_custom_prime_edt(&edt, cinfo);
    epan_dissect_run(&edt, cf_->cd_t, &rec, fdata, cinfo);
    epan_dissect_fill_in_columns(&edt, false, true);

    columns.reserve(static_cast<int>(cinfo->num_cols));
    for (unsigned i = 0; i < cinfo->num_cols; i++) {
        columns << QString::fromUtf8(get_column_text(cinfo, i));
    }

    epan_dissect_cleanup(&edt);
    wtap_rec_cleanup(&rec);
    return true;
}

void CaptureEngine::setProgress(double progress)
{
    if (progress < 0.0) progress = 0.0;
    if (progress > 1.0) progress = 1.0;
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
