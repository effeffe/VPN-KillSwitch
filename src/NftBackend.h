#pragma once
#include "Backend.h"

// Own table `inet vpnks`:
//   global       filter output, priority 0          killswitch
//   cg_filter    filter output, priority -10        cgroup methods
//   cg_mark      route output, priority mangle      cgroup split: mark (re-routes)
//   cg_nat       nat postrouting, priority srcnat   cgroup split: NAT onto the namespace link
class NftBackend : public Backend {
public:
    using Backend::Backend;
    QString name() const override { return QStringLiteral("nftables"); }
    bool arm(const QStringList &endpointIps, const QStringList &uplinks, QString *err) override;
    bool disarm(QString *err) override;
    bool isArmed() override;
    bool applyAppRules(const AppRuleSpec &s, QString *err) override;
    bool removeAppRules(QString *err) override;
    QString appRulesTag() override;
private:
    CmdResult nft(const QStringList &args) const { return m_r.run(QStringList{QStringLiteral("nft")} + args); }
    bool applyScript(const QString &script, QString *err) const;
    bool deleteChain(const QString &chain) const;
    void dropTableIfEmpty() const;
    static QString set(const QStringList &v) { return QStringLiteral("{ ") + v.join(QStringLiteral(", ")) + QStringLiteral(" }"); }
    QString tunnelMatch() const { return QStringLiteral("oifname \"%1\"").arg(m_c.tunnelNft()); }
};
