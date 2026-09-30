#include "HelperConfig.h"
#include <QFile>
#include <QHostAddress>

bool HelperConfig::installed() { return QFile::exists(defaultPath()); }

HelperConfig HelperConfig::load(const QString &path)
{
    HelperConfig c;
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return c;
    const QStringList lines = QString::fromUtf8(f.readAll()).split(QLatin1Char('\n'));
    for (QString line : lines) {
        const int hash = line.indexOf(QLatin1Char('#'));
        if (hash >= 0) line.truncate(hash);
        const int eq = line.indexOf(QLatin1Char('='));
        if (eq <= 0) continue;
        const QString key = line.left(eq).trimmed();
        QString val = line.mid(eq + 1).trimmed();
        if (val.size() >= 2 && val.startsWith(QLatin1Char('"')) && val.endsWith(QLatin1Char('"'))) val = val.mid(1, val.size() - 2);
        if (val.isEmpty()) continue;
        if (key == QLatin1String("NS")) c.ns = val;
        else if (key == QLatin1String("TUNNEL")) c.tunnel = val;
        else if (key == QLatin1String("HOST_ADDR")) c.hostAddr = val;
        else if (key == QLatin1String("NS_ADDR")) c.nsAddr = val;
        else if (key == QLatin1String("HOST_IF")) c.hostIf = val;
        else if (key == QLatin1String("MODE")) c.mode = val;
        else if (key == QLatin1String("SLICE")) c.slice = val;
        else if (key == QLatin1String("CGROUP_MARK")) c.mark = val.toLower();
    }
    return c;
}

QString HelperConfig::hostNetwork() const
{
    bool ok = false;
    const int len = hostAddr.section(QLatin1Char('/'), 1, 1).toInt(&ok);
    const QHostAddress a(hostIp());
    if (!ok || len < 0 || len > 32 || a.protocol() != QAbstractSocket::IPv4Protocol) return QString();
    const quint32 mask = len == 0 ? 0u : (0xFFFFFFFFu << (32 - len));
    return QHostAddress(a.toIPv4Address() & mask).toString() + QLatin1Char('/') + QString::number(len);
}
