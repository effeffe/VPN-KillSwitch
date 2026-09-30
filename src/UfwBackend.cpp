#include "UfwBackend.h"
#include "NetInfo.h"
#include <QRegularExpression>

const QString UfwBackend::kTag = QStringLiteral("vpnks-global");

bool UfwBackend::allowTunnel(const QString &dev, QString *err) const
{
    if (dev.isEmpty()) return true;
    CmdResult r = ufw({QStringLiteral("allow"), QStringLiteral("out"), QStringLiteral("on"), dev, QStringLiteral("to"), QStringLiteral("any"), QStringLiteral("comment"), kTag});
    if (!r.ok() && err) *err = r.err;
    return r.ok();
}

bool UfwBackend::arm(const QStringList &eps, const QStringList &up, QString *err)
{
    bool ok = true;
    auto allow = [&](QStringList a) { CmdResult r = ufw(QStringList{QStringLiteral("allow"), QStringLiteral("out")} + a + QStringList{QStringLiteral("comment"), kTag}); if (!r.ok()) { ok = false; if (err) *err = r.err; } };
    for (const QString &l : m_c.allowedCidrs()) allow({QStringLiteral("to"), l});
    if (const QString h = m_c.hostLinkIf(); !h.isEmpty()) allow({QStringLiteral("on"), h, QStringLiteral("to"), QStringLiteral("any")});
    for (const QString &e : eps) {
        if (up.isEmpty()) allow({QStringLiteral("to"), e});
        for (const QString &u : up) allow({QStringLiteral("on"), u, QStringLiteral("to"), e});
    }
    for (const QString &d : m_c.dns) allow({QStringLiteral("to"), d, QStringLiteral("port"), QStringLiteral("53")});
    ok = allowTunnel(NetInfo::tunnelDevice(m_c.tunnelPrefix), err) && ok;
    CmdResult r = ufw({QStringLiteral("default"), QStringLiteral("deny"), QStringLiteral("outgoing")});
    if (!r.ok()) { ok = false; if (err) *err = r.err; }
    return ok;
}

bool UfwBackend::disarm(QString *err)
{
    bool ok = ufw({QStringLiteral("default"), QStringLiteral("allow"), QStringLiteral("outgoing")}).ok();
    CmdResult s = ufw({QStringLiteral("status"), QStringLiteral("numbered")});
    static const QRegularExpression re(QStringLiteral("^\\[\\s*(\\d+)\\]"));
    QList<int> nums;
    for (const QString &line : s.out.split(QLatin1Char('\n'))) {
        if (!line.contains(kTag)) continue;
        const auto m = re.match(line.trimmed());
        if (m.hasMatch()) nums << m.captured(1).toInt();
    }
    std::sort(nums.begin(), nums.end(), std::greater<int>());
    for (int n : nums) {
        CmdResult d = ufw({QStringLiteral("--force"), QStringLiteral("delete"), QString::number(n)});
        if (!d.ok()) { ok = false; if (err) *err = d.err; }
    }
    return ok;
}

bool UfwBackend::isArmed()
{
    CmdResult s = ufw({QStringLiteral("status"), QStringLiteral("verbose")});
    return s.ok() && s.out.contains(QStringLiteral("deny (outgoing)"));
}

void UfwBackend::tunnelChanged(const QString &dev)
{
    if (dev.isEmpty() || !isArmed()) return;
    CmdResult s = ufw({QStringLiteral("status")});
    if (s.out.contains(QStringLiteral("on ") + dev)) return;
    allowTunnel(dev, nullptr);
}
