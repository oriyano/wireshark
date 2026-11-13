/* engineworker.cpp
 *
 * Kitsune - the engine thread.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "engineworker.h"

#include <QElapsedTimer>
#include <QFileInfo>
#include <QRegularExpression>

#include <algorithm>

#include <glib.h>

#include <app/application_flavor.h>
#include <epan/addr_resolv.h>
#include <epan/cfile.h>
#include <epan/column.h>
#include <epan/dfilter/dfilter.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data_sequence.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/secrets.h>
#include <epan/tvbuff.h>
#include <epan/ftypes/ftypes.h>
#include <wiretap/wtap.h>

extern capture_file cfile;

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

EngineWorker::EngineWorker(QObject *parent) :
    QObject(parent),
    cf_(&cfile)
{
}

EngineWorker::~EngineWorker()
{
    closeFile();
}

void EngineWorker::openFile(const QString &path, int generation)
{
    closeFile();
    file_generation_ = generation;
    cancel = false;

    if (!fields_registered_) {
        inventory_.registerFields();
        fields_registered_ = true;
    }

    int err = 0;
    char *err_info = nullptr;
    const QByteArray native_path = path.toUtf8();
    wtap *wth = wtap_open_offline(native_path.constData(), WTAP_TYPE_AUTO, &err, &err_info, true,
                                  application_configuration_environment_prefix());
    if (!wth) {
        QString message = tr("Couldn't open %1: %2").arg(QFileInfo(path).fileName(),
                                                        QString::fromUtf8(wtap_strerror(err)));
        if (err_info) {
            message += QStringLiteral(" (%1)").arg(QString::fromUtf8(err_info));
            g_free(err_info);
        }
        emit openFailed(message, file_generation_);
        return;
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
    const qint64 size = wtap_file_size(wth, &err);
    emit opened(path, QString::fromUtf8(wtap_file_type_subtype_description(cf_->cd_t)), size, file_generation_);

    runFirstPass();
}

/* Sequential read of the whole file: builds the frame table, lets the
 * dissectors build their per-conversation state, and feeds the host
 * inventory. */
void EngineWorker::runFirstPass()
{
    QElapsedTimer timer;
    timer.start();

    int err = 0;
    char *err_info = nullptr;
    int64_t data_offset = 0;
    wtap_rec rec;
    static frame_data ref_frame;
    const int64_t file_size = wtap_file_size(cf_->provider.wth, &err);
    err = 0;

    inventory_.clear();
    /* Building a protocol tree roughly doubles the cost of dissection,
     * so only packets that can tell the inventory something beyond
     * addresses and counts get one (see HostInventory::peek). */
    epan_dissect_t *edt_tree = epan_dissect_new(cf_->epan, true, false);
    epan_dissect_t *edt_fast = epan_dissect_new(cf_->epan, false, false);
    wtap_rec_init(&rec, 2048);

    qint64 last_report = 0;
    while (!cancel && wtap_read(cf_->provider.wth, &rec, &err, &err_info, &data_offset)) {
        frame_data fdlocal;
        frame_data_init(&fdlocal, cf_->count + 1, &rec, data_offset, cf_->cum_bytes);
        frame_data_set_before_dissect(&fdlocal, &cf_->elapsed_time, &cf_->provider.ref, cf_->provider.prev_dis);
        if (cf_->provider.ref == &fdlocal) {
            ref_frame = fdlocal;
            cf_->provider.ref = &ref_frame;
        }

        const HostInventory::Peek peek = rec.rec_type == REC_TYPE_PACKET
            ? HostInventory::peek(rec.rec_header.packet_header.pkt_encap, ws_buffer_start_ptr(&rec.data),
                                  rec.rec_header.packet_header.caplen)
            : HostInventory::Peek();
        epan_dissect_t *edt = peek.needsTree ? edt_tree : edt_fast;
        if (peek.needsTree) {
            inventory_.primeDissection(edt);
        }
        epan_dissect_run(edt, cf_->cd_t, &rec, &fdlocal, NULL);
        inventory_.addPacket(edt, &fdlocal, peek);

        frame_data_set_after_dissect(&fdlocal, &cf_->cum_bytes);
        cf_->provider.prev_cap = cf_->provider.prev_dis =
            frame_data_sequence_add(cf_->provider.frames, &fdlocal);
        cf_->count++;
        epan_dissect_reset(edt);
        wtap_rec_reset(&rec);

        const qint64 now = timer.elapsed();
        if (now - last_report >= 100) {
            last_report = now;
            const double progress = file_size > 0 ?
                static_cast<double>(wtap_read_so_far(cf_->provider.wth)) / static_cast<double>(file_size) : 0.0;
            emit loadProgress(progress, static_cast<int>(cf_->count), file_generation_);
        }
    }

    epan_dissect_free(edt_tree);
    epan_dissect_free(edt_fast);
    wtap_rec_cleanup(&rec);
    wtap_sequential_close(cf_->provider.wth);
    postseq_cleanup_all_protocols();
    cf_->provider.prev_dis = nullptr;
    cf_->provider.prev_cap = nullptr;
    cf_->state = FILE_READ_DONE;

    QString error;
    if (err != 0) {
        error = QString::fromUtf8(wtap_strerror(err));
        if (err_info) {
            error += QStringLiteral(" (%1)").arg(QString::fromUtf8(err_info));
        }
    }
    g_free(err_info);

    QString duration;
    if (cf_->count > 0) {
        frame_data *first = frame_data_sequence_find(cf_->provider.frames, 1);
        frame_data *last = frame_data_sequence_find(cf_->provider.frames, cf_->count);
        if (first && last) {
            qint64 secs = qMax<qint64>(0, last->abs_ts.secs - first->abs_ts.secs);
            duration = QStringLiteral("%1:%2:%3")
                .arg(secs / 3600, 2, 10, QLatin1Char('0'))
                .arg((secs / 60) % 60, 2, 10, QLatin1Char('0'))
                .arg(secs % 60, 2, 10, QLatin1Char('0'));
        }
    }

    const qint64 elapsed = timer.elapsed();
    if (cancel) {
        return;     /* closed or replaced while loading */
    }
    emit inventoryReady(inventory_.snapshot(), file_generation_);
    emit loaded(static_cast<int>(cf_->count), elapsed, duration, error, file_generation_);
}

void EngineWorker::closeFile()
{
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
    inventory_.clear();
}

bool EngineWorker::dissectRow(quint32 frame, PacketRow &row)
{
    if (cf_->state != FILE_READ_DONE || !cf_->provider.frames || frame == 0 || frame > cf_->count) {
        return false;
    }
    frame_data *fdata = frame_data_sequence_find(cf_->provider.frames, frame);
    if (!fdata) {
        return false;
    }

    column_info *cinfo = &cf_->cinfo;
    row.frame = frame;
    row.columns.clear();

    wtap_rec rec;
    wtap_rec_init(&rec, 2048);
    int err = 0;
    char *err_info = nullptr;
    if (!wtap_seek_read(cf_->provider.wth, fdata->file_off, &rec, &err, &err_info)) {
        g_free(err_info);
        col_fill_in_error(cinfo, fdata, false, true);
    } else {
        epan_dissect_t edt;
        epan_dissect_init(&edt, cf_->epan, have_custom_cols(cinfo), false);
        col_custom_prime_edt(&edt, cinfo);
        epan_dissect_run(&edt, cf_->cd_t, &rec, fdata, cinfo);
        epan_dissect_fill_in_columns(&edt, false, true);
        epan_dissect_cleanup(&edt);
    }
    for (unsigned i = 0; i < cinfo->num_cols; i++) {
        row.columns << QString::fromUtf8(get_column_text(cinfo, i));
    }
    wtap_rec_cleanup(&rec);
    return true;
}

QStringList EngineWorker::columnsNow(quint32 frame)
{
    PacketRow row;
    dissectRow(frame, row);
    return row.columns;
}

void EngineWorker::requestRows(const QVector<quint32> &frames, int generation)
{
    QVector<PacketRow> rows;
    rows.reserve(frames.size());
    for (quint32 frame : frames) {
        PacketRow row;
        if (dissectRow(frame, row)) {
            rows.append(row);
        }
    }
    emit rowsReady(rows, generation);
}

/* ------------------------------------------------------------------ */
/* Packet details                                                      */

struct TreeBuildContext {
    ProtoNode *parent;
    tvbuff_t *frame_tvb;
};

static int severityOf(const field_info *fi)
{
    switch (FI_GET_FLAG(fi, PI_SEVERITY_MASK)) {
    case PI_ERROR: return 4;
    case PI_WARN: return 3;
    case PI_NOTE: return 2;
    case PI_CHAT: return 1;
    default: return 0;
    }
}

static void buildNode(proto_node *node, void *data)
{
    TreeBuildContext *ctx = static_cast<TreeBuildContext *>(data);
    field_info *fi = PNODE_FINFO(node);
    if (!fi || proto_item_is_hidden(node)) {
        return;
    }

    ProtoNodePtr item = ProtoNodePtr::create();
    item->parent = ctx->parent;
    if (fi->rep) {
        item->label = QString::fromUtf8(fi->rep->representation);
    } else {
        char label[ITEM_LABEL_LENGTH];
        proto_item_fill_label(fi, label, NULL);
        item->label = QString::fromUtf8(label);
    }
    if (fi->hfinfo) {
        item->field = QString::fromUtf8(fi->hfinfo->abbrev);
        item->isProtocol = fi->hfinfo->type == FT_PROTOCOL;
        if (fi->value && fi->hfinfo->type != FT_PROTOCOL && fi->hfinfo->type != FT_NONE) {
            char *repr = fvalue_to_string_repr(NULL, fi->value, FTREPR_DFILTER, fi->hfinfo->display);
            if (repr) {
                item->filterValue = QString::fromUtf8(repr);
                g_free(repr);
            }
        }
    }
    if (fi->ds_tvb == ctx->frame_tvb && fi->length > 0) {
        item->start = static_cast<int>(fi->start);
        item->length = static_cast<int>(fi->length);
    }
    item->severity = severityOf(fi);

    ctx->parent->children.append(item);

    if (node->first_child) {
        TreeBuildContext child_ctx { item.data(), ctx->frame_tvb };
        proto_tree_children_foreach(node, buildNode, &child_ctx);
    }
}

void EngineWorker::requestDetails(quint32 frame, int generation)
{
    PacketDetails details;
    details.frame = frame;
    details.root = ProtoNodePtr::create();

    frame_data *fdata = (cf_->state == FILE_READ_DONE && cf_->provider.frames && frame > 0 && frame <= cf_->count)
                        ? frame_data_sequence_find(cf_->provider.frames, frame) : nullptr;
    if (!fdata) {
        emit detailsReady(details, generation);
        return;
    }

    wtap_rec rec;
    wtap_rec_init(&rec, 2048);
    int err = 0;
    char *err_info = nullptr;
    if (wtap_seek_read(cf_->provider.wth, fdata->file_off, &rec, &err, &err_info)) {
        epan_dissect_t edt;
        epan_dissect_init(&edt, cf_->epan, true, true);
        epan_dissect_run(&edt, cf_->cd_t, &rec, fdata, NULL);

        TreeBuildContext ctx { details.root.data(), edt.tvb };
        proto_tree_children_foreach(edt.tree, buildNode, &ctx);

        if (edt.tvb) {
            const unsigned length = tvb_captured_length(edt.tvb);
            const uint8_t *bytes = tvb_get_ptr(edt.tvb, 0, length);
            details.bytes = QByteArray(reinterpret_cast<const char *>(bytes), static_cast<int>(length));
        }
        epan_dissect_cleanup(&edt);
    }
    g_free(err_info);
    wtap_rec_cleanup(&rec);
    emit detailsReady(details, generation);
}

/* ------------------------------------------------------------------ */
/* Display filters                                                     */

/* Every protocol and field name, for "did you mean" suggestions. */
static const QStringList &allFieldNames()
{
    static QStringList names;
    if (!names.isEmpty()) {
        return names;
    }
    void *proto_cookie = nullptr;
    for (int proto_id = proto_get_first_protocol(&proto_cookie); proto_id != -1;
         proto_id = proto_get_next_protocol(&proto_cookie)) {
        names << QString::fromUtf8(proto_get_protocol_filter_name(proto_id));
        void *field_cookie = nullptr;
        for (header_field_info *hfinfo = proto_get_first_protocol_field(proto_id, &field_cookie); hfinfo;
             hfinfo = proto_get_next_protocol_field(proto_id, &field_cookie)) {
            if (hfinfo->same_name_prev_id != -1) {
                continue;
            }
            names << QString::fromUtf8(hfinfo->abbrev);
        }
    }
    return names;
}

static int editDistance(const QString &a, const QString &b, int limit)
{
    if (qAbs(a.size() - b.size()) > limit) {
        return limit + 1;
    }
    QVector<int> prev(b.size() + 1), cur(b.size() + 1);
    for (int j = 0; j <= b.size(); j++) prev[j] = j;
    for (int i = 1; i <= a.size(); i++) {
        cur[0] = i;
        int row_min = cur[0];
        for (int j = 1; j <= b.size(); j++) {
            const int cost = a[i - 1] == b[j - 1] ? 0 : 1;
            cur[j] = qMin(qMin(prev[j] + 1, cur[j - 1] + 1), prev[j - 1] + cost);
            row_min = qMin(row_min, cur[j]);
        }
        if (row_min > limit) {
            return limit + 1;
        }
        std::swap(prev, cur);
    }
    return prev[b.size()];
}

/* The closest known field names to a misspelled one, best first. */
static QStringList suggestFields(const QString &name)
{
    const QString lower = name.toLower();
    const int limit = lower.size() <= 4 ? 1 : 2;
    QList<QPair<int, QString>> scored;
    for (const QString &candidate : allFieldNames()) {
        int d = editDistance(lower, candidate, limit);
        if (d <= limit) {
            scored.append({ d * 1000 + static_cast<int>(candidate.size()), candidate });
        }
    }
    std::sort(scored.begin(), scored.end());
    QStringList out;
    for (int i = 0; i < scored.size() && out.size() < 3; i++) {
        out << scored[i].second;
    }
    return out;
}

/* Turn the engine's error message into one a student can act on. */
QString EngineWorker::friendlyFilterError(const QString &message)
{
    static const QRegularExpression unknown_field(QStringLiteral("^\"(.*)\" is not a valid protocol or protocol field\\.$"));
    static const QRegularExpression unexpected(QStringLiteral("^\"(.*)\" was unexpected in this context\\.$"));
    QRegularExpressionMatch m = unknown_field.match(message);
    if (m.hasMatch()) {
        const QString name = m.captured(1);
        const QStringList suggestions = suggestFields(name);
        QString out = tr("There is no protocol or field called \"%1\".").arg(name);
        if (!suggestions.isEmpty()) {
            out += QLatin1Char(' ') + tr("Did you mean %1?").arg(suggestions.join(tr(", ")));
        } else if (name.contains(QLatin1Char(' '))) {
            out += QLatin1Char(' ') + tr("Put quotes around text values, e.g. http.host == \"example.com\".");
        } else {
            out += QLatin1Char(' ') + tr("Field names look like ip.addr, tcp.port or dns.qry.name.");
        }
        return out;
    }
    m = unexpected.match(message);
    if (m.hasMatch()) {
        const QString token = m.captured(1);
        if (token == QLatin1String("=")) {
            return tr("Use == to compare values, e.g. ip.addr == 10.0.0.1.");
        }
        if (token == QLatin1String("&") || token == QLatin1String("|")) {
            return tr("Use && (or \"and\") and || (or \"or\") to combine conditions.");
        }
        return tr("\"%1\" doesn't belong there. Check for a missing operator such as ==, or a missing \"and\" / \"or\" between conditions.").arg(token);
    }
    if (message.startsWith(QLatin1String("Unexpected end of filter expression"))) {
        return tr("The filter stops too early. Finish the comparison, e.g. tcp.port == 443, or close any open parenthesis.");
    }
    if (message.contains(QLatin1String("is not a valid number"))) {
        return message + QLatin1Char(' ') + tr("Numbers are written like 80 or 0x50.");
    }
    return message;
}

void EngineWorker::checkFilter(const QString &text, int generation)
{
    const QByteArray utf8 = text.toUtf8();
    dfilter_t *dfcode = nullptr;
    df_error_t *df_err = nullptr;
    if (dfilter_compile(utf8.constData(), &dfcode, &df_err)) {
        dfilter_free(dfcode);
        emit filterChecked(text, true, QString(), -1, 0, generation);
        return;
    }
    QString message = friendlyFilterError(df_err && df_err->msg ? QString::fromUtf8(df_err->msg) : tr("Invalid filter"));
    int start = -1, length = 0;
    if (df_err && df_err->loc.col_start >= 0) {
        /* The engine reports byte offsets; convert to characters. */
        start = static_cast<int>(QString::fromUtf8(utf8.left(static_cast<int>(df_err->loc.col_start))).size());
        length = static_cast<int>(QString::fromUtf8(utf8.mid(static_cast<int>(df_err->loc.col_start),
                                                             static_cast<int>(df_err->loc.col_len))).size());
    }
    df_error_free(&df_err);
    emit filterChecked(text, false, message, start, length, generation);
}

void EngineWorker::applyFilter(const QString &text, int generation)
{
    QElapsedTimer timer;
    timer.start();
    QVector<quint32> matches;

    if (cf_->state != FILE_READ_DONE || !cf_->provider.frames) {
        emit filterApplied(text, matches, 0, generation);
        return;
    }

    const QString trimmed = text.trimmed();
    if (trimmed.isEmpty()) {
        matches.reserve(static_cast<int>(cf_->count));
        for (quint32 frame = 1; frame <= cf_->count; frame++) {
            matches.append(frame);
        }
        emit filterApplied(text, matches, timer.elapsed(), generation);
        return;
    }

    const QByteArray utf8 = trimmed.toUtf8();
    dfilter_t *dfcode = nullptr;
    df_error_t *df_err = nullptr;
    if (!dfilter_compile(utf8.constData(), &dfcode, &df_err) || !dfcode) {
        const QString message = friendlyFilterError(df_err && df_err->msg ? QString::fromUtf8(df_err->msg) : tr("Invalid filter"));
        df_error_free(&df_err);
        emit filterFailed(text, message, generation);
        return;
    }

    cancel = false;
    wtap_rec rec;
    wtap_rec_init(&rec, 2048);
    epan_dissect_t edt;
    epan_dissect_init(&edt, cf_->epan, true, false);
    qint64 last_report = 0;

    for (quint32 frame = 1; frame <= cf_->count && !cancel; frame++) {
        frame_data *fdata = frame_data_sequence_find(cf_->provider.frames, frame);
        int err = 0;
        char *err_info = nullptr;
        if (!fdata || !wtap_seek_read(cf_->provider.wth, fdata->file_off, &rec, &err, &err_info)) {
            g_free(err_info);
            continue;
        }
        epan_dissect_prime_with_dfilter(&edt, dfcode);
        epan_dissect_run(&edt, cf_->cd_t, &rec, fdata, NULL);
        if (dfilter_apply_edt(dfcode, &edt)) {
            matches.append(frame);
        }
        epan_dissect_reset(&edt);
        wtap_rec_reset(&rec);

        const qint64 now = timer.elapsed();
        if (now - last_report >= 100) {
            last_report = now;
            emit filterProgress(static_cast<double>(frame) / cf_->count);
        }
    }

    epan_dissect_cleanup(&edt);
    wtap_rec_cleanup(&rec);
    dfilter_free(dfcode);

    if (cancel) {
        return;     /* a newer filter replaced this one */
    }
    emit filterApplied(text, matches, timer.elapsed(), generation);
}
