/* captureengine.h
 *
 * Kitsune - a QML interface on top of the Wireshark engine.
 *
 * CaptureEngine owns the libwireshark session for one capture file.
 * The first pass over the file runs on a worker thread so the
 * interface stays responsive; after that, individual packets are
 * dissected on demand on the GUI thread, which is the only thread
 * that touches epan once loading has finished.
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

#include <atomic>

#include <epan/cfile.h>

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
    Q_PROPERTY(QString fileTypeName READ fileTypeName NOTIFY loaded)
    Q_PROPERTY(QString lastError READ lastError NOTIFY errorOccurred)

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

    /* Column layout from the active profile. */
    int columnCount() const;
    QString columnTitle(int column) const;

    /* Dissect frame number (1-based) and return its column strings.
     * GUI thread only, and only after loading has finished. */
    bool dissectColumns(uint32_t frame_num, QStringList &columns);

    /* Peak resident memory of this process, in bytes. */
    static qint64 peakMemoryBytes();

signals:
    void fileChanged();
    void loadingChanged();
    void loadProgressChanged();
    void packetCountChanged();
    void loaded();
    void errorOccurred(const QString &message);

private slots:
    void onLoadFinished(int err, const QString &err_message, qint64 elapsed_ms);

private:
    void runFirstPass();
    void setProgress(double progress);

    capture_file *cf_;
    QThread *load_thread_;
    std::atomic<bool> cancel_load_;
    QString file_path_;
    bool loading_;
    double load_progress_;
    int packet_count_;
    qint64 load_time_ms_;
    QString duration_;
    QString file_type_name_;
    QString last_error_;
    int64_t file_size_;
};

#endif // KITSUNE_CAPTUREENGINE_H
