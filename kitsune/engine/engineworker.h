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

private:
    bool dissectRow(quint32 frame, PacketRow &row);
    void runFirstPass();

    capture_file *cf_;
    HostInventory inventory_;
    bool fields_registered_ = false;
    int file_generation_ = 0;
};

#endif // KITSUNE_ENGINEWORKER_H
