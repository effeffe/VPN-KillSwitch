#include "IptablesBackend.h"

static const QString G   = QStringLiteral("VPNKS_GLOBAL");
static const QString CG  = QStringLiteral("VPNKS_CGROUP");
static const QString CGM = QStringLiteral("VPNKS_CGMARK");
static const QString CGN = QStringLiteral("VPNKS_CGNAT");
static const QString LEGACY_APPS = QStringLiteral("VPNKS_APPS"); // per-app chain of earlier versions
static const QString FILTER = QStringLiteral("filter"), MANGLE = QStringLiteral("mangle"), NAT = QStringLiteral("nat");
static const QString OUTPUT = QStringLiteral("OUTPUT"), POSTROUTING = QStringLiteral("POSTROUTING");
static const QStringList BINS{QStringLiteral("iptables"), QStringLiteral("ip6tables")};
static QStringList tagged(const QString &t) { return {QStringLiteral("-m"), QStringLiteral("comment"), QStringLiteral("--comment"), t}; }

bool IptablesBackend::dropChain(const QString &bin, const QString &table, const QString &hook, const QString &chain) const
{
    const QStringList t{QStringLiteral("-t"), table};
    for (int i = 0; i < 8 && ipt(bin, t + QStringList{QStringLiteral("-D"), hook, QStringLiteral("-j"), chain}).ok(); ++i) {}
    ipt(bin, t + QStringList{QStringLiteral("-F"), chain});
    return ipt(bin, t + QStringList{QStringLiteral("-X"), chain}).ok();
}

bool IptablesBackend::replaceChain(const QString &bin, const QString &table, const QString &hook, const QString &chain,
                                   const QList<QStringList> &body, QString *err) const
{
    // fill a new chain, jump to it, then drop the old one and take its name: never a moment without rules
    const QStringList t{QStringLiteral("-t"), table};
    const QString fresh = chain + QStringLiteral("_NEW");
    dropChain(bin, table, hook, fresh);   // leftover of an interrupted run
    const CmdResult n = ipt(bin, t + QStringList{QStringLiteral("-N"), fresh});
    if (!n.ok()) { if (err) *err = n.err; return false; }
    for (const QStringList &r : body) {
        const CmdResult c = ipt(bin, t + QStringList{QStringLiteral("-A"), fresh} + r);
        if (!c.ok()) { if (err) *err = c.err; dropChain(bin, table, hook, fresh); return false; }
    }
    const CmdResult j = ipt(bin, t + QStringList{QStringLiteral("-I"), hook, QStringLiteral("1"), QStringLiteral("-j"), fresh});
    if (!j.ok()) { if (err) *err = j.err; dropChain(bin, table, hook, fresh); return false; }
    dropChain(bin, table, hook, chain);
    const CmdResult e = ipt(bin, t + QStringList{QStringLiteral("-E"), fresh, chain});
    if (!e.ok()) { if (err) *err = e.err; return false; }
    return true;
}

QList<QStringList> IptablesBackend::globalBody(const QString &bin, const QStringList &eps, const QStringList &up) const
{
    const bool v4 = bin == BINS[0];
    const QString T = QString::fromLatin1(kGlobalTag);
    const QString A = QStringLiteral("ACCEPT");
    QList<QStringList> R;
    auto add = [&](QStringList b) { R << (b + tagged(T)); };
    add({QStringLiteral("-o"), QStringLiteral("lo"), QStringLiteral("-j"), A});
    if (v4) {
        add({QStringLiteral("-m"), QStringLiteral("addrtype"), QStringLiteral("--dst-type"), QStringLiteral("LOCAL"), QStringLiteral("-j"), A});
        for (const QString &l : m_c.allowedCidrs()) add({QStringLiteral("-d"), l, QStringLiteral("-j"), A});
        if (const QString h = m_c.hostLinkIf(); !h.isEmpty()) add({QStringLiteral("-o"), h, QStringLiteral("-j"), A});
        for (const QString &e : eps) {
            if (up.isEmpty()) add({QStringLiteral("-d"), e, QStringLiteral("-j"), A});
            for (const QString &u : up) add({QStringLiteral("-o"), u, QStringLiteral("-d"), e, QStringLiteral("-j"), A});
        }
        for (const QString &d : m_c.dns) {
            add({QStringLiteral("-d"), d, QStringLiteral("-p"), QStringLiteral("udp"), QStringLiteral("--dport"), QStringLiteral("53"), QStringLiteral("-j"), A});
            add({QStringLiteral("-d"), d, QStringLiteral("-p"), QStringLiteral("tcp"), QStringLiteral("--dport"), QStringLiteral("53"), QStringLiteral("-j"), A});
        }
        add({QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), A});
    } else if (!m_c.blockIpv6) {
        add({QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), A});
    }
    add({QStringLiteral("-j"), QStringLiteral("REJECT")});
    return R;
}

bool IptablesBackend::arm(const QStringList &eps, const QStringList &up, QString *err)
{
    bool ok = true;
    for (const QString &bin : BINS) {
        dropChain(bin, FILTER, OUTPUT, LEGACY_APPS);
        ok = replaceChain(bin, FILTER, OUTPUT, G, globalBody(bin, eps, up), err) && ok;
    }
    return ok;
}

bool IptablesBackend::disarm(QString *err)
{
    bool ok = true;
    for (const QString &bin : BINS) dropChain(bin, FILTER, OUTPUT, LEGACY_APPS);
    for (const QString &bin : BINS)
        if (!dropChain(bin, FILTER, OUTPUT, G)) { ok = false; if (err) *err = QStringLiteral("could not remove chain %1 (%2)").arg(G, bin); }
    return ok;
}

bool IptablesBackend::isArmed()
{
    return ipt(BINS[0], {QStringLiteral("-C"), OUTPUT, QStringLiteral("-j"), G}).ok();
}

bool IptablesBackend::applyAppRules(const AppRuleSpec &s, QString *err)
{
    bool ok = true;
    const QString A = QStringLiteral("ACCEPT");
    const QStringList M{QStringLiteral("-m"), QStringLiteral("cgroup"), QStringLiteral("--path"), s.cgroupPath};
    if (!s.split) { dropChain(BINS[0], MANGLE, OUTPUT, CGM); dropChain(BINS[0], NAT, POSTROUTING, CGN); }
    for (const QString &bin : BINS) {
        const bool v4 = bin == BINS[0];
        QList<QStringList> body;
        auto add = [&](QStringList b) { body << (M + b + tagged(s.tag)); };
        add({QStringLiteral("-o"), QStringLiteral("lo"), QStringLiteral("-j"), A});
        if (v4) {
            add({QStringLiteral("-m"), QStringLiteral("addrtype"), QStringLiteral("--dst-type"), QStringLiteral("LOCAL"), QStringLiteral("-j"), A});
            for (const QString &l : m_c.allowedCidrs()) add({QStringLiteral("-d"), l, QStringLiteral("-j"), A});
            for (const QString &e : s.endpoints) {
                if (s.uplinks.isEmpty()) add({QStringLiteral("-d"), e, QStringLiteral("-j"), A});
                for (const QString &u : s.uplinks) add({QStringLiteral("-o"), u, QStringLiteral("-d"), e, QStringLiteral("-j"), A});
            }
            add({QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), A});
            if (s.split) add({QStringLiteral("-o"), s.hostIf, QStringLiteral("-j"), A});
        } else if (!m_c.blockIpv6) {
            add({QStringLiteral("-o"), m_c.tunnelIpt(), QStringLiteral("-j"), A});
        }
        add({QStringLiteral("-j"), QStringLiteral("REJECT")});
        ok = replaceChain(bin, FILTER, OUTPUT, CG, body, err) && ok;
    }
    if (s.split) {
        const QString &b4 = BINS[0];
        ok = replaceChain(b4, MANGLE, OUTPUT, CGM, {M + QStringList{QStringLiteral("-j"), QStringLiteral("MARK"), QStringLiteral("--set-mark"), s.mark} + tagged(s.tag)}, err) && ok;
        ok = replaceChain(b4, NAT, POSTROUTING, CGN, {QStringList{QStringLiteral("-o"), s.hostIf, QStringLiteral("-m"), QStringLiteral("mark"),
                              QStringLiteral("--mark"), s.mark, QStringLiteral("-j"), QStringLiteral("MASQUERADE")} + tagged(s.tag)}, err) && ok;
    }
    return ok;
}

bool IptablesBackend::removeAppRules(QString *)
{
    for (const QString &bin : BINS) dropChain(bin, FILTER, OUTPUT, CG);
    dropChain(BINS[0], MANGLE, OUTPUT, CGM);
    dropChain(BINS[0], NAT, POSTROUTING, CGN);
    return true;
}

QString IptablesBackend::appRulesTag()
{
    const CmdResult r = ipt(BINS[0], {QStringLiteral("-S"), CG});
    return r.ok() ? findAppsTag(r.out) : QString();
}
