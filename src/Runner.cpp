#include "Runner.h"
#include <QProcess>

CmdResult Runner::run(const QStringList &argv, bool elevate, const QByteArray &stdinData) const
{
    QStringList cmd = argv;
    if (elevate && elevation != QLatin1String("none")) cmd.prepend(elevation);

    if (logger) logger(QStringLiteral("$ ") + cmd.join(QLatin1Char(' ')));
    if (dryRun) {
        CmdResult r; r.exit = 0;
        // queries must report "absent" in dry-run so arm/disarm show the full command set
        const bool query = argv.contains(QStringLiteral("--query-rule")) || argv.contains(QStringLiteral("-C"))
                        || argv.contains(QStringLiteral("list")) || argv.contains(QStringLiteral("status"))
                        || argv.contains(QStringLiteral("--get-all-rules")) || argv.contains(QStringLiteral("-S"));
        if (query) r.exit = 1;
        return r;
    }

    QProcess p;
    p.start(cmd.first(), cmd.mid(1));
    CmdResult r;
    if (!p.waitForStarted(5000)) { r.err = QStringLiteral("could not start ") + cmd.first(); if (logger) logger(QStringLiteral("  ! ") + r.err); return r; }
    if (!stdinData.isEmpty()) p.write(stdinData);
    p.closeWriteChannel();
    if (!p.waitForFinished(60000)) { p.kill(); r.err = QStringLiteral("timed out"); if (logger) logger(QStringLiteral("  ! timed out")); return r; }
    r.exit = p.exitCode();
    r.out  = QString::fromUtf8(p.readAllStandardOutput());
    r.err  = QString::fromUtf8(p.readAllStandardError()).trimmed();
    if (logger && r.exit != 0) logger(QStringLiteral("  -> exit %1 %2").arg(r.exit).arg(r.err));
    return r;
}
