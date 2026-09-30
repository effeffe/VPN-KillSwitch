#include "Killswitch.h"
#include <QHostAddress>
#include <QHostInfo>

Killswitch::Killswitch() { config.load(); reload(); }

void Killswitch::reload()
{
    runner.elevation = config.elevation;
    m_b = Backend::create(runner, config);
}

QStringList Killswitch::resolvedEndpoints(QString *err) const
{
    QStringList out;
    for (const QString &e : config.endpoints) {
        const QString h = e.trimmed();
        if (h.isEmpty()) continue;
        QHostAddress a(h);
        if (!a.isNull()) { if (a.protocol() == QAbstractSocket::IPv4Protocol) out << h; continue; }
        const QHostInfo info = QHostInfo::fromName(h);
        bool any = false;
        for (const QHostAddress &x : info.addresses())
            if (x.protocol() == QAbstractSocket::IPv4Protocol) { out << x.toString(); any = true; }
        if (!any && err) *err += QStringLiteral("could not resolve %1\n").arg(h);
    }
    out.removeDuplicates();
    return out;
}

bool Killswitch::arm(QString *err)
{
    QString rerr;
    const QStringList eps = resolvedEndpoints(&rerr);
    if (eps.isEmpty() && !config.endpoints.isEmpty()) { if (err) *err = rerr + QStringLiteral("refusing to arm without a reachable VPN endpoint"); return false; }
    if (err && !rerr.isEmpty()) *err = rerr;
    const QStringList up = config.uplinks();
    if (runner.logger) runner.logger(QStringLiteral("# uplinks: %1  endpoints: %2").arg(up.isEmpty() ? QStringLiteral("(any)") : up.join(QLatin1Char(' ')), eps.join(QLatin1Char(' '))));
    return m_b->arm(eps, up, err);
}

bool Killswitch::disarm(QString *err) { return m_b->disarm(err); }
bool Killswitch::isArmed() { return m_b->isArmed(); }

