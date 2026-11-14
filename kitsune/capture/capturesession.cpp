/* capturesession.cpp
 *
 * Kitsune - live capture through dumpcap.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "capturesession.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QLocalServer>
#include <QLocalSocket>
#include <QStandardPaths>
#include <QVariantMap>

#include "engine/captureengine.h"

using namespace SyncPipe;

CaptureSession::CaptureSession(CaptureEngine *engine, QObject *parent) :
    QObject(parent),
    engine_(engine)
{
}

CaptureSession::~CaptureSession()
{
    if (process_) {
        process_->disconnect(this);
        process_->terminate();
        if (!process_->waitForFinished(2000)) {
            process_->kill();
            process_->waitForFinished(1000);
        }
    }
}

QString CaptureSession::dumpcapPath()
{
    const QString dir = QCoreApplication::applicationDirPath();
#ifdef Q_OS_WIN
    return QDir(dir).filePath(QStringLiteral("dumpcap.exe"));
#else
    return QDir(dir).filePath(QStringLiteral("dumpcap"));
#endif
}

void CaptureSession::refreshInterfaces()
{
    if (lister_) {
        return;
    }
    const QString dumpcap = dumpcapPath();
    if (!QFileInfo::exists(dumpcap)) {
        fail(tr("dumpcap, the capture helper, is not installed next to Kitsune (%1).").arg(dumpcap));
        return;
    }
    listing_ = true;
    emit interfacesChanged();
    lister_ = new QProcess(this);
    connect(lister_, &QProcess::finished, this, [this](int, QProcess::ExitStatus) {
        const QString output = QString::fromLocal8Bit(lister_->readAllStandardOutput());
        const QString errors = QString::fromLocal8Bit(lister_->readAllStandardError()).trimmed();
        interfaces_ = SyncPipe::parseInterfaceList(output);
        if (interfaces_.isEmpty() && !errors.isEmpty()) {
            fail(tr("No capture interfaces: %1").arg(errors));
        }
        lister_->deleteLater();
        lister_ = nullptr;
        listing_ = false;
        emit interfacesChanged();
    });
    lister_->start(dumpcap, { QStringLiteral("-D") });
}

bool CaptureSession::start(const QString &interface_name)
{
    if (process_) {
        return false;
    }
    const QString dumpcap = dumpcapPath();
    if (!QFileInfo::exists(dumpcap)) {
        fail(tr("dumpcap, the capture helper, is not installed next to Kitsune (%1).").arg(dumpcap));
        return false;
    }

    output_dir_ = QDir(QStandardPaths::writableLocation(QStandardPaths::TempLocation)).filePath(QStringLiteral("kitsune"));
    QDir().mkpath(output_dir_);
    const QString stamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss"));
    const QString output = QDir(output_dir_).filePath(QStringLiteral("capture-%1.pcapng").arg(stamp));

    QStringList args = SyncPipe::captureArguments(interface_name, capture_filter_, output, ring_buffer_, ring_files_, ring_megabytes_);
#ifdef Q_OS_WIN
    /* On Windows dumpcap stops when its signal pipe has data or breaks. */
    const QString pipe_id = QStringLiteral("kitsune.%1").arg(QCoreApplication::applicationPid());
    signal_server_ = new QLocalServer(this);
    signal_server_->listen(QStringLiteral("wireshark.%1.signal").arg(pipe_id));
    connect(signal_server_, &QLocalServer::newConnection, this, [this]() {
        signal_socket_ = signal_server_->nextPendingConnection();
    });
    args << QStringLiteral("--signal-pipe") << pipe_id;
#endif

    interface_name_ = interface_name;
    packets_ = 0;
    drops_ = 0;
    files_written_ = 0;
    current_file_.clear();
    last_error_.clear();
    buffer_.clear();
    stopping_ = false;

    process_ = new QProcess(this);
    process_->setProcessChannelMode(QProcess::SeparateChannels);
    connect(process_, &QProcess::readyReadStandardError, this, &CaptureSession::onReadyRead);
    connect(process_, &QProcess::finished, this, &CaptureSession::onFinished);
    connect(process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            fail(tr("Couldn't start dumpcap: %1").arg(process_->errorString()));
            process_->deleteLater();
            process_ = nullptr;
            emit runningChanged();
        }
    });
    process_->start(dumpcap, args);
    emit runningChanged();
    emit statsChanged();
    return true;
}

void CaptureSession::stop()
{
    if (!process_ || stopping_) {
        return;
    }
    stopping_ = true;
    emit runningChanged();
#ifdef Q_OS_WIN
    if (signal_socket_) {
        signal_socket_->write("Q");
        signal_socket_->flush();
    } else {
        process_->kill();
    }
#else
    process_->terminate();      /* SIGTERM: dumpcap finishes the file and exits */
#endif
}

void CaptureSession::onReadyRead()
{
    buffer_ += process_->readAllStandardError();
    for (const SyncPipe::Message &m : SyncPipe::parseMessages(buffer_)) {
        handle(m);
    }
}

void CaptureSession::handle(const SyncPipe::Message &message)
{
    switch (message.type) {
    case sp_file: {
        /* A new file: the first one, or the next in a ring buffer. */
        if (!current_file_.isEmpty()) {
            engine_->finishLive();
        }
        current_file_ = QString::fromUtf8(message.body);
        files_written_++;
        engine_->startLive(current_file_);
        emit statsChanged();
        break;
    }
    case sp_packet_count: {
        const int count = message.body.toInt();
        packets_ += count;
        engine_->continueLive(count);
        emit statsChanged();
        break;
    }
    case sp_drops:
        drops_ = message.body.toLongLong();
        emit statsChanged();
        break;
    case sp_bad_filter:
        /* "<interface index>:<pcap's message>" */
        fail(tr("The capture filter isn't valid (%1). Capture filters use BPF syntax, such as \"tcp port 443\" or \"host 10.0.0.5\".")
                 .arg(QString::fromUtf8(message.body).section(QLatin1Char(':'), 1, -1).section(QLatin1Char(':'), -1).trimmed()));
        break;
    case sp_error: {
        /* An error holds two messages of its own: the error and a hint. */
        const QStringList parts = errorText(message.body);
        if (!parts.isEmpty()) {
            fail(parts.join(QLatin1Char(' ')));
        }
        break;
    }
    case sp_success:
    default:
        break;
    }
}

void CaptureSession::onFinished(int, QProcess::ExitStatus)
{
    if (process_) {
        buffer_ += process_->readAllStandardError();
        for (const SyncPipe::Message &m : SyncPipe::parseMessages(buffer_)) {
            handle(m);
        }
        process_->deleteLater();
        process_ = nullptr;
    }
    if (!current_file_.isEmpty()) {
        engine_->finishLive();
    }
    delete signal_server_;
    signal_server_ = nullptr;
    signal_socket_ = nullptr;
    stopping_ = false;
    emit runningChanged();
    emit statsChanged();
}

void CaptureSession::fail(const QString &message)
{
    last_error_ = message;
    emit errorOccurred(message);
}

void CaptureSession::setRingBuffer(bool on)
{
    if (on != ring_buffer_) {
        ring_buffer_ = on;
        emit optionsChanged();
    }
}

void CaptureSession::setRingFiles(int files)
{
    files = qBound(2, files, 1000);
    if (files != ring_files_) {
        ring_files_ = files;
        emit optionsChanged();
    }
}

void CaptureSession::setRingFileMegabytes(int megabytes)
{
    megabytes = qBound(1, megabytes, 100000);
    if (megabytes != ring_megabytes_) {
        ring_megabytes_ = megabytes;
        emit optionsChanged();
    }
}

void CaptureSession::setCaptureFilter(const QString &filter)
{
    if (filter != capture_filter_) {
        capture_filter_ = filter;
        emit optionsChanged();
    }
}
