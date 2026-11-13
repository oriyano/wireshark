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
    settings_.setValue(QStringLiteral("ui/themeMode"), mode);
    emit themeModeChanged();
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
