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

public:
    explicit KitsuneSettings(QObject *parent = nullptr);

    int themeMode() const { return theme_mode_; }
    void setThemeMode(int mode);
    bool systemPrefersDark() const;

signals:
    void themeModeChanged();
    void systemPrefersDarkChanged();

private:
    QSettings settings_;
    int theme_mode_;
};

#endif // KITSUNE_KITSUNESETTINGS_H
