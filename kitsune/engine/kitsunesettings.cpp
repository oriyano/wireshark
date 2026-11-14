/* kitsunesettings.cpp
 *
 * Kitsune - persistent user interface settings.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "kitsunesettings.h"

#include <QGuiApplication>
#include <QPalette>
#include <QStyleHints>

KitsuneSettings::KitsuneSettings(QObject *parent) :
    QObject(parent),
    settings_(QStringLiteral("Kitsune"), QStringLiteral("Kitsune")),
    theme_mode_(settings_.value(QStringLiteral("ui/themeMode"), 2).toInt())
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged,
            this, &KitsuneSettings::systemPrefersDarkChanged);
#endif
}

void KitsuneSettings::setThemeMode(int mode)
{
    if (mode < 0 || mode > 2 || mode == theme_mode_) {
        return;
    }
    theme_mode_ = mode;
    if (save_theme_) {
        settings_.setValue(QStringLiteral("ui/themeMode"), mode);
    }
    emit themeModeChanged();
}

void KitsuneSettings::setThemeModeForSession(int mode)
{
    save_theme_ = false;
    setThemeMode(mode);
}

static QString subnetKey(const QString &cidr)
{
    /* QSettings treats '/' as a group separator. */
    QString key = cidr;
    key.replace(QLatin1Char('/'), QLatin1Char('_'));
    return QStringLiteral("subnetNames/") + key;
}

QString KitsuneSettings::subnetName(const QString &cidr) const
{
    return settings_.value(subnetKey(cidr)).toString();
}

void KitsuneSettings::setSubnetName(const QString &cidr, const QString &name)
{
    const QString trimmed = name.trimmed();
    if (trimmed == subnetName(cidr)) {
        return;
    }
    if (trimmed.isEmpty()) {
        settings_.remove(subnetKey(cidr));
    } else {
        settings_.setValue(subnetKey(cidr), trimmed);
    }
    emit subnetNamesChanged();
}

bool KitsuneSettings::systemPrefersDark() const
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    Qt::ColorScheme scheme = QGuiApplication::styleHints()->colorScheme();
    if (scheme != Qt::ColorScheme::Unknown) {
        return scheme == Qt::ColorScheme::Dark;
    }
#endif
    /* Older Qt, or the platform doesn't say: judge by the window color. */
    const QPalette palette = QGuiApplication::palette();
    return palette.color(QPalette::Window).lightness() < palette.color(QPalette::WindowText).lightness();
}

bool KitsuneSettings::largeFileMode() const
{
    return settings_.value(QStringLiteral("engine/largeFileMode"), false).toBool();
}

void KitsuneSettings::setLargeFileMode(bool on)
{
    if (on == largeFileMode()) {
        return;
    }
    settings_.setValue(QStringLiteral("engine/largeFileMode"), on);
    emit largeFileModeChanged();
}
