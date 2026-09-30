#pragma once
#include "Backend.h"
#include <QList>

// Own chains jumped from the built-in ones, in iptables (+ ip6tables for filter):
//   filter OUTPUT      -> VPNKS_GLOBAL (killswitch), VPNKS_CGROUP (cgroup methods)
//   mangle OUTPUT      -> VPNKS_CGMARK (cgroup split: mark)
//   nat    POSTROUTING -> VPNKS_CGNAT  (cgroup split: NAT onto the namespace link)
class IptablesBackend : public Backend {
public:
    using Backend::Backend;
    QString name() const override { return QStringLiteral("iptables"); }
    bool arm(const QStringList &endpointIps, const QStringList &uplinks, QString *err) override;
    bool disarm(QString *err) override;
    bool isArmed() override;
    bool applyAppRules(const AppRuleSpec &s, QString *err) override;
    bool removeAppRules(QString *err) override;
    QString appRulesTag() override;
private:
    CmdResult ipt(const QString &bin, const QStringList &args) const { return m_r.run(QStringList{bin} + args); }
    bool ensureChain(const QString &bin, const QString &table, const QString &hook, const QString &chain, QString *err) const;
    bool dropChain(const QString &bin, const QString &table, const QString &hook, const QString &chain) const;
    QList<QStringList> globalBody(const QString &bin, const QStringList &eps, const QStringList &up) const;
};
