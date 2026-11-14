/* capturesession.h
 *
 * Kitsune - live capture through dumpcap.
 *
 * dumpcap does the capturing, with whatever privileges it was given at
 * install time, so Kitsune itself never needs them. It runs as a
 * capture child ("-Z none") and reports on stderr in the sync pipe
 * format: which file it is writing, how many packets it has added, and
 * any errors. Kitsune reads that file as it grows.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_CAPTURESESSION_H
#define KITSUNE_CAPTURESESSION_H

#include <QObject>
#include <QProcess>
#include <QStringList>
#include <QVariantList>

#include "capture/syncpipe.h"

class CaptureEngine;
class QLocalServer;
class QLocalSocket;

class CaptureSession : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList interfaces READ interfaces NOTIFY interfacesChanged)
    Q_PROPERTY(bool listingInterfaces READ listingInterfaces NOTIFY interfacesChanged)
    Q_PROPERTY(bool running READ running NOTIFY runningChanged)
    Q_PROPERTY(bool stopping READ stopping NOTIFY runningChanged)
    Q_PROPERTY(QString interfaceName READ interfaceName NOTIFY runningChanged)
    Q_PROPERTY(qint64 packets READ packets NOTIFY statsChanged)
    Q_PROPERTY(qint64 drops READ drops NOTIFY statsChanged)
    Q_PROPERTY(int filesWritten READ filesWritten NOTIFY statsChanged)
    Q_PROPERTY(QString currentFile READ currentFile NOTIFY statsChanged)
    Q_PROPERTY(QString lastError READ lastError NOTIFY errorOccurred)

    /* Ring buffer: keep only the newest files, each up to a size. */
    Q_PROPERTY(bool ringBuffer READ ringBuffer WRITE setRingBuffer NOTIFY optionsChanged)
    Q_PROPERTY(int ringFiles READ ringFiles WRITE setRingFiles NOTIFY optionsChanged)
    Q_PROPERTY(int ringFileMegabytes READ ringFileMegabytes WRITE setRingFileMegabytes NOTIFY optionsChanged)
    Q_PROPERTY(QString captureFilter READ captureFilter WRITE setCaptureFilter NOTIFY optionsChanged)

public:
    explicit CaptureSession(CaptureEngine *engine, QObject *parent = nullptr);
    ~CaptureSession() override;

    /* dumpcap next to the executable, as installed. */
    static QString dumpcapPath();

    Q_INVOKABLE void refreshInterfaces();
    Q_INVOKABLE bool start(const QString &interface_name);
    Q_INVOKABLE void stop();

    QVariantList interfaces() const { return interfaces_; }
    bool listingInterfaces() const { return listing_; }
    bool running() const { return process_ != nullptr; }
    bool stopping() const { return stopping_; }
    QString interfaceName() const { return interface_name_; }
    qint64 packets() const { return packets_; }
    qint64 drops() const { return drops_; }
    int filesWritten() const { return files_written_; }
    QString currentFile() const { return current_file_; }
    QString lastError() const { return last_error_; }

    bool ringBuffer() const { return ring_buffer_; }
    void setRingBuffer(bool on);
    int ringFiles() const { return ring_files_; }
    void setRingFiles(int files);
    int ringFileMegabytes() const { return ring_megabytes_; }
    void setRingFileMegabytes(int megabytes);
    QString captureFilter() const { return capture_filter_; }
    void setCaptureFilter(const QString &filter);

signals:
    void interfacesChanged();
    void runningChanged();
    void statsChanged();
    void optionsChanged();
    void errorOccurred(const QString &message);

private slots:
    void onReadyRead();
    void onFinished(int exit_code, QProcess::ExitStatus status);

private:
    void handle(const SyncPipe::Message &message);
    void fail(const QString &message);

    CaptureEngine *engine_;
    QProcess *process_ = nullptr;
    QProcess *lister_ = nullptr;
    QLocalServer *signal_server_ = nullptr;     /* Windows: dumpcap's stop channel */
    QLocalSocket *signal_socket_ = nullptr;
    QByteArray buffer_;
    QVariantList interfaces_;
    bool listing_ = false;
    bool stopping_ = false;
    QString interface_name_;
    qint64 packets_ = 0;
    qint64 drops_ = 0;
    int files_written_ = 0;
    QString current_file_;
    QString last_error_;
    QString output_dir_;

    bool ring_buffer_ = false;
    int ring_files_ = 5;
    int ring_megabytes_ = 100;
    QString capture_filter_;
};

#endif // KITSUNE_CAPTURESESSION_H
