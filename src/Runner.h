#pragma once
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <functional>

struct CmdResult {
    int exit = -1;
    QString out, err;
    bool ok() const { return exit == 0; }
};

// Runs external commands, optionally through pkexec/sudo, with a dry-run mode
// that only logs what would be executed.
class Runner {
public:
    QString elevation = QStringLiteral("pkexec"); // pkexec | sudo | none
    bool dryRun = false;
    std::function<void(const QString &)> logger;

    CmdResult run(const QStringList &argv, bool elevate = true, const QByteArray &stdinData = {}) const;
};
