#include "FirewalldBackend.h"

static QStringList tagged(const QString &tag) { return {QStringLiteral("-m"), QStringLiteral("comment"), QStringLiteral("--comment"), tag}; }

QList<QStringList> FirewalldBackend::globalRules(const QStringList &eps, const QStringList &up) const
{
    const QString T = QString::fromLatin1(kGlobalTag);
    QList<QStringList> R;
    auto v4 = [&](int prio, QStringList body) { R << (QStringList{QStringLiteral("ipv4"), QStringLiteral("filter"), QStringLiteral("OUTPUT"), QString::number(prio)} + body + tagged(T)); };
    auto v6 = [&](int prio, QStringList body) { R << (QStringList{QStringLiteral("ipv6"), QStringLiteral("filter"), QStringLiteral("OUTPUT"), QString::number(prio)} + body + tagged(T)); };

    v4(0, {QStringLiteral("-o"), QStringLiteral("lo"), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    v4(0, {QStringLiteral("-m"), QStringLiteral("addrtype"), QStringLiteral("--dst-type"), QStringLiteral("LOCAL"), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    for (const QString &l : m_c.allowedCidrs()) v4(1, {QStringLiteral("-d"), l, QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    // host-only link to the VPN namespace: reaches namespaced services, or (cgroup split) the tunnel
    if (const QString h = m_c.hostLinkIf(); !h.isEmpty()) v4(1, {QStringLiteral("-o"), h, QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    for (const QString &e : eps) {
        if (up.isEmpty()) v4(2, {QStringLiteral("-d"), e, QStringLiteral("-j"), QStringLiteral("ACCEPT")});
        for (const QString &u : up) v4(2, {QStringLiteral("-o"), u, QStringLiteral("-d"), e, QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    }
    for (const QString &d : m_c.dns) {
        v4(2, {QStringLiteral("-d"), d, QStringLiteral("-p"), QStringLiteral("udp"), QStringLiteral("--dport"), QStringLiteral("53"), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
        v4(2, {QStringLiteral("-d"), d, QStringLiteral("-p"), QStringLiteral("tcp"), QStringLiteral("--dport"), QStringLiteral("53"), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    }
    v4(3, {QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    v4(10, {QStringLiteral("-j"), QStringLiteral("REJECT")});

    v6(0, {QStringLiteral("-o"), QStringLiteral("lo"), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    if (!m_c.blockIpv6) v6(3, {QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), QStringLiteral("ACCEPT")});
    v6(10, {QStringLiteral("-j"), QStringLiteral("REJECT")});
    return R;
}

bool FirewalldBackend::sync(const QList<QStringList> &rules, const QString &tag, QString *err) const
{
    // add what is missing before removing what is stale, so the set is never absent
    QStringList want;
    for (const QStringList &r : rules) want << r.join(QLatin1Char(' '));
    bool ok = true;
    for (const QStringList &scope : {QStringList{}, QStringList{QStringLiteral("--permanent")}}) {
        const CmdResult cur = fw(scope + QStringList{QStringLiteral("--direct"), QStringLiteral("--get-all-rules")});
        if (!cur.ok() && !m_r.dryRun) { ok = false; if (err) *err = cur.err; continue; }
        QStringList have;
        for (const QString &l : cur.out.split(QLatin1Char('\n'), Qt::SkipEmptyParts))
            if (l.contains(tag)) have << l.simplified();
        for (int i = 0; i < rules.size(); ++i) {
            if (have.contains(want[i])) continue;
            const CmdResult a = fw(scope + QStringList{QStringLiteral("--direct"), QStringLiteral("--add-rule")} + rules[i]);
            if (!a.ok()) { ok = false; if (err) *err = a.err; }
        }
        for (const QString &l : std::as_const(have)) {
            if (want.contains(l)) continue;
            const CmdResult d = fw(scope + QStringList{QStringLiteral("--direct"), QStringLiteral("--remove-rule")} + l.split(QLatin1Char(' ')));
            if (!d.ok()) { ok = false; if (err) *err = d.err; }
        }
    }
    return ok;
}

bool FirewalldBackend::removeWhere(const std::function<bool(const QString &)> &match, QString *err) const
{
    bool ok = true;
    for (const QStringList &scope : {QStringList{}, QStringList{QStringLiteral("--permanent")}}) {
        CmdResult r = fw(scope + QStringList{QStringLiteral("--direct"), QStringLiteral("--get-all-rules")});
        if (!r.ok()) { ok = false; if (err) *err = r.err; continue; }
        const QStringList lines = r.out.split(QLatin1Char('\n'), Qt::SkipEmptyParts);
        for (const QString &line : lines) {
            if (!match(line)) continue;
            CmdResult d = fw(scope + QStringList{QStringLiteral("--direct"), QStringLiteral("--remove-rule")} + line.simplified().split(QLatin1Char(' ')));
            if (!d.ok()) { ok = false; if (err) *err = d.err; }
        }
    }
    return ok;
}

bool FirewalldBackend::hasTag(const QString &tag) const
{
    CmdResult r = fw({QStringLiteral("--direct"), QStringLiteral("--get-all-rules")});
    return r.ok() && r.out.contains(tag);
}

void FirewalldBackend::removeLegacyAppRules() const
{
    // Earlier versions installed per-app rules with `-m cgroup --path .../vpnks-<id>.slice`
    // (runtime and --permanent). The kernel resolves that path when the rule is inserted, so a
    // --permanent copy fails at boot and can keep firewalld from loading its direct rules.
    removeWhere([](const QString &l) {
        return l.contains(QStringLiteral("-m cgroup")) && l.contains(QStringLiteral("vpnks")) && !l.contains(QLatin1String(kAppsTag));
    }, nullptr);
}

bool FirewalldBackend::arm(const QStringList &eps, const QStringList &up, QString *err)
{
    removeLegacyAppRules();
    return sync(globalRules(eps, up), QString::fromLatin1(kGlobalTag), err);
}
bool FirewalldBackend::disarm(QString *err)
{
    removeLegacyAppRules();
    return removeTagged(QString::fromLatin1(kGlobalTag), err);
}
bool FirewalldBackend::isArmed() { return hasTag(QString::fromLatin1(kGlobalTag)); }


QList<QStringList> FirewalldBackend::appRules(const AppRuleSpec &s) const
{
    const QStringList CG{QStringLiteral("-m"), QStringLiteral("cgroup"), QStringLiteral("--path"), s.cgroupPath};
    const QString A = QStringLiteral("ACCEPT");
    QList<QStringList> R;
    auto f = [&](const QString &fam, int prio, QStringList body) {
        R << (QStringList{fam, QStringLiteral("filter"), QStringLiteral("OUTPUT"), QString::number(prio)} + CG + body + tagged(s.tag));
    };
    const QString v4 = QStringLiteral("ipv4"), v6 = QStringLiteral("ipv6");
    // priorities 4/5: after the global accepts (0-3), before the global REJECT (10)
    f(v4, 4, {QStringLiteral("-o"), QStringLiteral("lo"), QStringLiteral("-j"), A});
    f(v4, 4, {QStringLiteral("-m"), QStringLiteral("addrtype"), QStringLiteral("--dst-type"), QStringLiteral("LOCAL"), QStringLiteral("-j"), A});
    for (const QString &l : m_c.allowedCidrs()) f(v4, 4, {QStringLiteral("-d"), l, QStringLiteral("-j"), A});
    for (const QString &e : s.endpoints) {
        if (s.uplinks.isEmpty()) f(v4, 4, {QStringLiteral("-d"), e, QStringLiteral("-j"), A});
        for (const QString &u : s.uplinks) f(v4, 4, {QStringLiteral("-o"), u, QStringLiteral("-d"), e, QStringLiteral("-j"), A});
    }
    f(v4, 4, {QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), A});
    if (s.split) f(v4, 4, {QStringLiteral("-o"), s.hostIf, QStringLiteral("-j"), A});
    f(v4, 5, {QStringLiteral("-j"), QStringLiteral("REJECT")});
    f(v6, 4, {QStringLiteral("-o"), QStringLiteral("lo"), QStringLiteral("-j"), A});
    if (!m_c.blockIpv6) f(v6, 4, {QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), A});
    f(v6, 5, {QStringLiteral("-j"), QStringLiteral("REJECT")});
    if (s.split) {
        R << (QStringList{v4, QStringLiteral("mangle"), QStringLiteral("OUTPUT"), QStringLiteral("0")} + CG
              + QStringList{QStringLiteral("-j"), QStringLiteral("MARK"), QStringLiteral("--set-mark"), s.mark} + tagged(s.tag));
        R << (QStringList{v4, QStringLiteral("nat"), QStringLiteral("POSTROUTING"), QStringLiteral("0"), QStringLiteral("-o"), s.hostIf,
                          QStringLiteral("-m"), QStringLiteral("mark"), QStringLiteral("--mark"), s.mark, QStringLiteral("-j"), QStringLiteral("MASQUERADE")}
              + tagged(s.tag));
    }
    return R;
}

bool FirewalldBackend::applyAppRules(const AppRuleSpec &s, QString *err)
{
    return sync(appRules(s), QString::fromLatin1(kAppsTag), err);
}

bool FirewalldBackend::removeAppRules(QString *err) { return removeTagged(QLatin1String(kAppsTag), err); }

QString FirewalldBackend::appRulesTag()
{
    const CmdResult r = fw({QStringLiteral("--direct"), QStringLiteral("--get-all-rules")});
    return r.ok() ? findAppsTag(r.out) : QString();
}
