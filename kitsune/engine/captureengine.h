/* captureengine.h
 *
 * Kitsune - the GUI's handle on the dissection engine.
 *
 * CaptureEngine lives on the GUI thread and owns an EngineWorker on a
 * thread of its own. It turns the worker's results into properties
 * and signals for QML and the models, and never calls libwireshark
 * itself (except for one-time start-up and column titles).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_CAPTUREENGINE_H
#define KITSUNE_CAPTUREENGINE_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QThread>
#include <QUrl>
#include <QVector>

#include "enginetypes.h"

class EngineWorker;

class CaptureEngine : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString fileName READ fileName NOTIFY fileChanged)
    Q_PROPERTY(QString filePath READ filePath NOTIFY fileChanged)
    Q_PROPERTY(bool loading READ loading NOTIFY loadingChanged)
    Q_PROPERTY(bool hasFile READ hasFile NOTIFY fileChanged)
    Q_PROPERTY(double loadProgress READ loadProgress NOTIFY loadProgressChanged)
    Q_PROPERTY(int packetCount READ packetCount NOTIFY packetCountChanged)
    Q_PROPERTY(qint64 loadTimeMs READ loadTimeMs NOTIFY loaded)
    Q_PROPERTY(QString duration READ duration NOTIFY loaded)
    Q_PROPERTY(QString fileTypeName READ fileTypeName NOTIFY fileChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY errorOccurred)

    Q_PROPERTY(QString filterText READ filterText NOTIFY filterChanged)
    Q_PROPERTY(bool filtering READ filtering NOTIFY filterChanged)
    Q_PROPERTY(double filterProgress READ filterProgress NOTIFY filterProgressChanged)
    Q_PROPERTY(int displayedCount READ displayedCount NOTIFY displayedFramesChanged)
    Q_PROPERTY(qint64 filterTimeMs READ filterTimeMs NOTIFY displayedFramesChanged)

    Q_PROPERTY(int selectedFrame READ selectedFrame NOTIFY selectedFrameChanged)

    /* Large-file mode trades TCP analysis (retransmission and
     * lost-segment flags) for about a third less memory. Changing it
     * reloads the open file. */
    Q_PROPERTY(bool largeFileMode READ largeFileMode WRITE setLargeFileMode NOTIFY largeFileModeChanged)

public:
    explicit CaptureEngine(QObject *parent = nullptr);
    ~CaptureEngine() override;

    /* One-time libwireshark start-up. Call before creating an engine. */
    static bool initLibraries(const char *argv0);
    static void cleanupLibraries();

    Q_INVOKABLE bool openFile(const QUrl &url);
    bool openPath(const QString &path);
    Q_INVOKABLE void closeFile();
    Q_INVOKABLE QString formatCount(qint64 value) const;

    /* Display filters. checkFilter answers through filterChecked. */
    Q_INVOKABLE void checkFilter(const QString &text);
    Q_INVOKABLE void applyFilter(const QString &text);
    Q_INVOKABLE void cancelFilter();

    /* Select a packet; its details arrive through detailsReady. */
    Q_INVOKABLE void selectFrame(int frame);

    QString fileName() const;
    QString filePath() const { return file_path_; }
    bool loading() const { return loading_; }
    bool hasFile() const { return !file_path_.isEmpty(); }
    double loadProgress() const { return load_progress_; }
    int packetCount() const { return packet_count_; }
    qint64 loadTimeMs() const { return load_time_ms_; }
    QString duration() const { return duration_; }
    QString fileTypeName() const { return file_type_name_; }
    QString lastError() const { return last_error_; }
    QString filterText() const { return filter_text_; }
    bool filtering() const { return filtering_; }
    double filterProgress() const { return filter_progress_; }
    int displayedCount() const { return static_cast<int>(displayed_.size()); }
    qint64 filterTimeMs() const { return filter_time_ms_; }
    int selectedFrame() const { return selected_frame_; }
    bool largeFileMode() const { return large_file_mode_; }
    void setLargeFileMode(bool on);

    const QVector<quint32> &displayedFrames() const { return displayed_; }
    const HostInventorySnapshot &inventory() const { return inventory_; }

    /* Column layout from the active profile. */
    int columnCount() const;
    QString columnTitle(int column) const;

    /* Ask the engine for rows; they arrive through rowsReady. */
    void requestRows(const QVector<quint32> &frames);
    /* Blocking variant, for the command-line benchmark only. */
    QStringList columnsBlocking(quint32 frame);
    /* Blocking variant of applyFilter, for benchmarks and tests. */
    void applyFilterBlocking(const QString &text);

    static qint64 peakMemoryBytes();

signals:
    void fileChanged();
    void loadingChanged();
    void loadProgressChanged();
    void packetCountChanged();
    void loaded();
    void errorOccurred(const QString &message);

    void filterChanged();
    void filterProgressChanged();
    void filterChecked(const QString &text, bool valid, const QString &message, int errorStart, int errorLength);
    void displayedFramesChanged();

    void rowsReady(const QVector<PacketRow> &rows);
    void selectedFrameChanged();
    void detailsReady(const PacketDetails &details);
    void inventoryChanged();
    void largeFileModeChanged();

private slots:
    void onOpened(const QString &path, const QString &file_type, qint64 file_size, int generation);
    void onOpenFailed(const QString &message, int generation);
    void onLoadProgress(double progress, int packets, int generation);
    void onLoaded(int packets, qint64 elapsed_ms, const QString &duration, const QString &error, int generation);
    void onInventoryReady(const HostInventorySnapshot &snapshot, int generation);
    void onRowsReady(const QVector<PacketRow> &rows, int generation);
    void onDetailsReady(const PacketDetails &details, int generation);
    void onFilterChecked(const QString &text, bool valid, const QString &message, int start, int length, int generation);
    void onFilterProgress(double progress);
    void onFilterApplied(const QString &text, const QVector<quint32> &frames, qint64 elapsed_ms, int generation);
    void onFilterFailed(const QString &text, const QString &message, int generation);

private:
    void setProgress(double progress);

    QThread thread_;
    EngineWorker *worker_;

    int file_generation_ = 0;
    int filter_generation_ = 0;
    int check_generation_ = 0;
    int details_generation_ = 0;

    QString file_path_;
    bool loading_ = false;
    double load_progress_ = 0.0;
    int packet_count_ = 0;
    qint64 load_time_ms_ = 0;
    QString duration_;
    QString file_type_name_;
    QString last_error_;

    QString filter_text_;
    QString applied_filter_text_;
    bool filtering_ = false;
    double filter_progress_ = 0.0;
    qint64 filter_time_ms_ = 0;
    QVector<quint32> displayed_;

    int selected_frame_ = 0;
    bool large_file_mode_ = false;
    HostInventorySnapshot inventory_;
};

#endif // KITSUNE_CAPTUREENGINE_H
