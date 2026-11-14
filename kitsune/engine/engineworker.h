/* engineworker.h
 *
 * Kitsune - the engine thread.
 *
 * libwireshark is not thread-safe, so every call into it happens on
 * one dedicated thread, inside this object. The GUI talks to it only
 * through queued signals and slots, and gets back plain data
 * (enginetypes.h). The interface never waits on dissection.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_ENGINEWORKER_H
#define KITSUNE_ENGINEWORKER_H

#include <QObject>
#include <QString>
#include <QVector>

#include <atomic>

#include "enginetypes.h"
#include "hostinventory.h"

typedef struct _capture_file capture_file;
typedef struct epan_dfilter dfilter_t;

class EngineWorker : public QObject
{
    Q_OBJECT

public:
    explicit EngineWorker(QObject *parent = nullptr);
    ~EngineWorker() override;

    /* Long jobs (first pass, filtering) check this between packets. */
    std::atomic<bool> cancel{false};

    /* Blocking access for the command-line benchmark. */
    QStringList columnsNow(quint32 frame);

    /* Rewrite a display filter error in plain English, with "did you
     * mean" suggestions for misspelled field names. */
    static QString friendlyFilterError(const QString &message);

public slots:
    void openFile(const QString &path, int generation);

    /* Live capture: open a file that dumpcap is still writing, read
     * packets as dumpcap reports them, and finish once it stops. */
    void openLive(const QString &path, int generation);
    void continueLive(int new_packets, int generation);
    void finishLive(int generation);
    /* Large-file mode: turn TCP sequence analysis off to save memory.
     * Takes effect from the next file opened. */
    void setLargeFileMode(bool on);
    void closeFile();
    void requestRows(const QVector<quint32> &frames, int generation);
    void requestDetails(quint32 frame, int generation);
    void checkFilter(const QString &text, int generation);
    void applyFilter(const QString &text, int generation);

signals:
    void opened(const QString &path, const QString &file_type, qint64 file_size, int generation);
    void openFailed(const QString &message, int generation);
    void loadProgress(double progress, int packets, int generation);
    void loaded(int packets, qint64 elapsed_ms, const QString &duration, const QString &error, int generation);
    void inventoryReady(const HostInventorySnapshot &snapshot, int generation);
    void rowsReady(const QVector<PacketRow> &rows, int generation);
    void detailsReady(const PacketDetails &details, int generation);
    void filterChecked(const QString &text, bool valid, const QString &message, int error_start, int error_length, int generation);
    void filterProgress(double progress);
    void filterApplied(const QString &text, const QVector<quint32> &frames, qint64 elapsed_ms, int generation);
    void filterFailed(const QString &text, const QString &message, int generation);
    /* Live capture: the packet count so far, and the new frames that
     * pass the display filter (all new frames when there is none). */
    void liveProgress(int packets, const QVector<quint32> &new_displayed, const QString &duration, int generation);

private:
    bool dissectRow(quint32 frame, PacketRow &row);
    bool openWtap(const QString &path, int generation);
    void runFirstPass();
    /* The first pass, in pieces, so live capture can read as it goes. */
    void beginPass();
    qint64 readPackets(qint64 limit);       /* -1: to the end; returns packets read */
    void endPass();
    QString durationText() const;
    void finishLiveBatch(bool final);

    capture_file *cf_;
    HostInventory inventory_;
    bool fields_registered_ = false;
    int file_generation_ = 0;

    /* State of a first pass in progress. */
    struct Pass;
    Pass *pass_ = nullptr;
    bool live_ = false;
    /* Frames already read can be shown: all of them once the file is
       read, or those read so far in a live capture. */
    bool framesReadable() const;
    qint64 live_pending_ = 0;               /* packets dumpcap reported that we haven't read */
    qint64 live_last_inventory_ = 0;
    dfilter_t *live_dfcode_ = nullptr;      /* display filter applied to new packets */
};

#endif // KITSUNE_ENGINEWORKER_H
