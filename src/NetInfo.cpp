#include "NetInfo.h"
#include <QDir>
#include <QProcess>
#include <QRegularExpression>

namespace NetInfo {

QStringList defaultRouteDevices(const QString &tunnelPrefix)
{
    QStringList devs;
    static const QRegularExpression re(QStringLiteral("\\bdev\\s+(\\S+)"));
    for (const QString &fam : {QStringLiteral("-4"), QStringLiteral("-6")}) {
        QProcess p;
        p.start(QStringLiteral("ip"), {fam, QStringLiteral("-o"), QStringLiteral("route"), QStringLiteral("show"), QStringLiteral("default")});
        if (!p.waitForFinished(3000)) continue;
        for (const QString &line : QString::fromUtf8(p.readAllStandardOutput()).split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
            const auto m = re.match(line);
            if (!m.hasMatch()) continue;
            const QString d = m.captured(1);
            if (d.startsWith(tunnelPrefix) || devs.contains(d)) continue;
            devs << d;
        }
    }
    return devs;
}

QString tunnelDevice(const QString &prefix)
{
    const QStringList devs = QDir(QStringLiteral("/sys/class/net"))
        .entryList(QStringList{prefix + QLatin1Char('*')}, QDir::Dirs | QDir::NoDotAndDotDot);
    return devs.isEmpty() ? QString() : devs.first();
}

// nmcli -t output: fields separated by ':', with ':' and '\\' inside values backslash-escaped
QStringList splitTerse(const QString &line)
{
    QStringList out;
    QString cur;
    bool esc = false;
    for (const QChar ch : line) {
        if (esc) { cur += ch; esc = false; }
        else if (ch == QLatin1Char('\\')) esc = true;
        else if (ch == QLatin1Char(':')) { out << cur; cur.clear(); }
        else cur += ch;
    }
    out << cur;
    return out;
}

}
