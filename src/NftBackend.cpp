#include "NftBackend.h"
#include <QTemporaryFile>

bool NftBackend::applyScript(const QString &script, QString *err) const
{
    QTemporaryFile f(QStringLiteral("/tmp/vpnks-XXXXXX.nft"));
    if (!f.open()) { if (err) *err = QStringLiteral("cannot create temp file"); return false; }
    f.write(script.toUtf8());
    f.flush();
    f.setPermissions(QFile::ReadOwner | QFile::WriteOwner | QFile::ReadGroup | QFile::ReadOther);
    if (m_r.logger) m_r.logger(QStringLiteral("--- nft script ---\n") + script.trimmed());
    CmdResult r = nft({QStringLiteral("-f"), f.fileName()});
    if (!r.ok() && err) *err = r.err;
    return r.ok();
}

bool NftBackend::arm(const QStringList &eps, const QStringList &up, QString *err)
{
    // earlier versions kept cgroup-matched per-app rules in chain `apps`; drop it if present
    nft({QStringLiteral("delete"), QStringLiteral("chain"), QStringLiteral("inet"), QStringLiteral("vpnks"), QStringLiteral("apps")});

    const QStringList allowed = m_c.allowedCidrs();
    QString s;
    s += QStringLiteral("add table inet vpnks\n");
    s += QStringLiteral("add chain inet vpnks global { type filter hook output priority 0; policy accept; }\n");
    s += QStringLiteral("flush chain inet vpnks global\n");
    const QString C = QStringLiteral("add rule inet vpnks global ");
    const QString T = QStringLiteral(" comment \"vpnks:global\"\n");
    s += C + QStringLiteral("oifname \"lo\" accept") + T;
    s += C + QStringLiteral("fib daddr type local accept") + T;
    if (!allowed.isEmpty()) s += C + QStringLiteral("ip daddr ") + set(allowed) + QStringLiteral(" accept") + T;
    if (const QString h = m_c.hostLinkIf(); !h.isEmpty()) s += C + QStringLiteral("oifname \"%1\" accept").arg(h) + T;
    if (!eps.isEmpty()) {
        QString oif;
        if (!up.isEmpty()) { QStringList q; for (const QString &u : up) q << QStringLiteral("\"%1\"").arg(u); oif = QStringLiteral("oifname ") + set(q) + QLatin1Char(' '); }
        s += C + oif + QStringLiteral("ip daddr ") + set(eps) + QStringLiteral(" accept") + T;
    }
    if (!m_c.dns.isEmpty()) {
        s += C + QStringLiteral("ip daddr ") + set(m_c.dns) + QStringLiteral(" udp dport 53 accept") + T;
        s += C + QStringLiteral("ip daddr ") + set(m_c.dns) + QStringLiteral(" tcp dport 53 accept") + T;
    }
    s += C + (m_c.blockIpv6 ? QStringLiteral("meta nfproto ipv4 ") : QString()) + tunnelMatch() + QStringLiteral(" accept") + T;
    s += C + QStringLiteral("reject with icmpx type admin-prohibited") + T;
    return applyScript(s, err);
}

bool NftBackend::deleteChain(const QString &chain) const
{
    return nft({QStringLiteral("delete"), QStringLiteral("chain"), QStringLiteral("inet"), QStringLiteral("vpnks"), chain}).ok();
}

void NftBackend::dropTableIfEmpty() const
{
    const CmdResult r = nft({QStringLiteral("list"), QStringLiteral("table"), QStringLiteral("inet"), QStringLiteral("vpnks")});
    if (r.ok() && !r.out.contains(QStringLiteral("chain ")))
        nft({QStringLiteral("delete"), QStringLiteral("table"), QStringLiteral("inet"), QStringLiteral("vpnks")});
}

bool NftBackend::disarm(QString *err)
{
    // only the killswitch chain: the table may also hold the cgroup chains
    const CmdResult r = nft({QStringLiteral("delete"), QStringLiteral("chain"), QStringLiteral("inet"), QStringLiteral("vpnks"), QStringLiteral("global")});
    if (!r.ok() && !r.err.contains(QStringLiteral("No such file"))) { if (err) *err = r.err; return false; }
    dropTableIfEmpty();
    return true;
}

bool NftBackend::isArmed()
{
    return nft({QStringLiteral("list"), QStringLiteral("chain"), QStringLiteral("inet"), QStringLiteral("vpnks"), QStringLiteral("global")}).ok();
}

bool NftBackend::applyAppRules(const AppRuleSpec &s, QString *err)
{
    if (!s.split) { deleteChain(QStringLiteral("cg_mark")); deleteChain(QStringLiteral("cg_nat")); }
    const QStringList allowed = m_c.allowedCidrs();
    const QString M = QStringLiteral("socket cgroupv2 level %1 \"%2\" ").arg(s.cgroupPath.count(QLatin1Char('/')) + 1).arg(s.cgroupPath);
    const QString T = QStringLiteral(" comment \"%1\"\n").arg(s.tag);
    QString x;
    x += QStringLiteral("add table inet vpnks\n");
    x += QStringLiteral("add chain inet vpnks cg_filter { type filter hook output priority -10; policy accept; }\n");
    x += QStringLiteral("flush chain inet vpnks cg_filter\n");
    const QString C = QStringLiteral("add rule inet vpnks cg_filter ") + M;
    x += C + QStringLiteral("oifname \"lo\" accept") + T;
    x += C + QStringLiteral("fib daddr type local accept") + T;
    if (!allowed.isEmpty()) x += C + QStringLiteral("ip daddr ") + set(allowed) + QStringLiteral(" accept") + T;
    if (!s.endpoints.isEmpty()) {
        QString oif;
        if (!s.uplinks.isEmpty()) { QStringList q; for (const QString &u : s.uplinks) q << QStringLiteral("\"%1\"").arg(u); oif = QStringLiteral("oifname ") + set(q) + QLatin1Char(' '); }
        x += C + oif + QStringLiteral("ip daddr ") + set(s.endpoints) + QStringLiteral(" accept") + T;
    }
    x += C + (m_c.blockIpv6 ? QStringLiteral("meta nfproto ipv4 ") : QString()) + tunnelMatch() + QStringLiteral(" accept") + T;
    if (s.split) x += C + QStringLiteral("meta nfproto ipv4 oifname \"%1\" accept").arg(s.hostIf) + T;
    x += C + QStringLiteral("reject with icmpx type admin-prohibited") + T;
    if (s.split) {
        x += QStringLiteral("add chain inet vpnks cg_mark { type route hook output priority mangle; policy accept; }\n");
        x += QStringLiteral("flush chain inet vpnks cg_mark\n");
        x += QStringLiteral("add rule inet vpnks cg_mark ") + M + QStringLiteral("meta nfproto ipv4 meta mark set ") + s.mark + T;
        x += QStringLiteral("add chain inet vpnks cg_nat { type nat hook postrouting priority srcnat; policy accept; }\n");
        x += QStringLiteral("flush chain inet vpnks cg_nat\n");
        x += QStringLiteral("add rule inet vpnks cg_nat oifname \"%1\" meta mark %2 masquerade").arg(s.hostIf, s.mark) + T;
    }
    return applyScript(x, err);
}

bool NftBackend::removeAppRules(QString *)
{
    for (const QString &c : {QStringLiteral("cg_filter"), QStringLiteral("cg_mark"), QStringLiteral("cg_nat")}) deleteChain(c);
    dropTableIfEmpty();
    return true;
}

QString NftBackend::appRulesTag()
{
    const CmdResult r = nft({QStringLiteral("list"), QStringLiteral("chain"), QStringLiteral("inet"), QStringLiteral("vpnks"), QStringLiteral("cg_filter")});
    return r.ok() ? findAppsTag(r.out) : QString();
}
