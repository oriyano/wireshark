/* kitsunesettings.h
 *
 * Kitsune - persistent user interface settings.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef KITSUNE_KITSUNESETTINGS_H
#define KITSUNE_KITSUNESETTINGS_H

#include <QObject>
#include <QSettings>

class KitsuneSettings : public QObject
{
    Q_OBJECT
    /* 0 = follow the system's colors, 1 = light, 2 = dark */
    Q_PROPERTY(int themeMode READ themeMode WRITE setThemeMode NOTIFY themeModeChanged)
    /* True when the operating system reports a dark color scheme. */
    Q_PROPERTY(bool systemPrefersDark READ systemPrefersDark NOTIFY systemPrefersDarkChanged)
    /* Saved choice for CaptureEngine::largeFileMode. */
    Q_PROPERTY(bool largeFileMode READ largeFileMode WRITE setLargeFileMode NOTIFY largeFileModeChanged)

public:
    explicit KitsuneSettings(QObject *parent = nullptr);

    int themeMode() const { return theme_mode_; }
    void setThemeMode(int mode);
    bool systemPrefersDark() const;
    /* For a command-line run: change the theme without saving it. */
    void setThemeModeForSession(int mode);
    bool largeFileMode() const;
    void setLargeFileMode(bool on);

    /* Names the user gave subnets, keyed by CIDR. Empty if none. */
    Q_INVOKABLE QString subnetName(const QString &cidr) const;
    Q_INVOKABLE void setSubnetName(const QString &cidr, const QString &name);

signals:
    void themeModeChanged();
    void systemPrefersDarkChanged();
    void subnetNamesChanged();
    void largeFileModeChanged();

private:
    QSettings settings_;
    int theme_mode_;
    bool save_theme_ = true;
};

#endif // KITSUNE_KITSUNESETTINGS_H
