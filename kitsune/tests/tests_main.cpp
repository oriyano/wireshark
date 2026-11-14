/* tests_main.cpp
 *
 * Kitsune - runs every unit test suite.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <QCoreApplication>

int runHostInventoryTests(int argc, char *argv[]);
int runSyncPipeTests(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    int failures = 0;
    failures += runHostInventoryTests(argc, argv);
    failures += runSyncPipeTests(argc, argv);
    return failures;
}
