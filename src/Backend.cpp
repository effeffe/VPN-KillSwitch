#include "Backend.h"
#include "FirewalldBackend.h"
#include "IptablesBackend.h"
#include "NftBackend.h"
#include "UfwBackend.h"
#include <QRegularExpression>

std::unique_ptr<Backend> Backend::create(const Runner &r, const GlobalConfig &c)
{
    if (c.backend == QLatin1String("iptables")) return std::make_unique<IptablesBackend>(r, c);
    if (c.backend == QLatin1String("nftables")) return std::make_unique<NftBackend>(r, c);
    if (c.backend == QLatin1String("ufw"))      return std::make_unique<UfwBackend>(r, c);
    return std::make_unique<FirewalldBackend>(r, c);
}

QString Backend::findAppsTag(const QString &text)
{
    static const QRegularExpression re(QStringLiteral("vpnks:apps:[0-9a-f]+(-[0-9a-f]+)?"));
    const auto m = re.match(text);
    return m.hasMatch() ? m.captured(0) : QString();
}
