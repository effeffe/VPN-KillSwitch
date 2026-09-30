#include "Config.h"
#include <QSettings>
#include "HelperConfig.h"
#include "NetInfo.h"

static QStringList clean(QStringList l)
{
    QStringList out;
    for (const QString &x : l) if (!x.trimmed().isEmpty()) out << x.trimmed();
    return out;
}

void GlobalConfig::load()
{
    QSettings s;
    backend      = s.value(QStringLiteral("backend"), backend).toString();
    elevation    = s.value(QStringLiteral("elevation"), elevation).toString();
    tunnelPrefix = s.value(QStringLiteral("tunnelPrefix"), tunnelPrefix).toString();
    physIf       = s.value(QStringLiteral("physIf"), physIf).toString();
    lan          = clean(s.value(QStringLiteral("lan"), lan).toStringList());
    endpoints    = clean(s.value(QStringLiteral("endpoints"), endpoints).toStringList());
    dns          = clean(s.value(QStringLiteral("dns"), dns).toStringList());
    blockIpv6    = s.value(QStringLiteral("blockIpv6"), blockIpv6).toBool();
}

QStringList GlobalConfig::uplinks() const
{
    if (!physIf.trimmed().isEmpty()) return clean(physIf.split(QLatin1Char(',')));
    return NetInfo::defaultRouteDevices(tunnelPrefix);
}

QStringList GlobalConfig::allowedCidrs() const
{
    // The host-only link to the VPN namespace must survive an armed killswitch,
    // otherwise the desktop loses access to namespaced web UIs.
    QStringList l = lan;
    if (HelperConfig::installed()) {
        const QString h = HelperConfig::load().hostNetwork();
        if (!h.isEmpty() && !l.contains(h)) l << h;
    }
    return l;
}

QString GlobalConfig::hostLinkIf() const
{
    return HelperConfig::installed() ? HelperConfig::load().hostIf : QString();
}

void GlobalConfig::save() const
{
    QSettings s;
    s.setValue(QStringLiteral("backend"), backend);
    s.setValue(QStringLiteral("elevation"), elevation);
    s.setValue(QStringLiteral("tunnelPrefix"), tunnelPrefix);
    s.setValue(QStringLiteral("physIf"), physIf);
    s.setValue(QStringLiteral("lan"), lan);
    s.setValue(QStringLiteral("endpoints"), endpoints);
    s.setValue(QStringLiteral("dns"), dns);
    s.setValue(QStringLiteral("blockIpv6"), blockIpv6);
}
