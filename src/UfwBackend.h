#pragma once
#include "Backend.h"

// ufw: `default deny outgoing` + tagged allow rules. ufw cannot express interface
// wildcards, so the tunnel allow uses the concrete device name (re-added on reconnect
// via tunnelChanged).
class UfwBackend : public Backend {
public:
    using Backend::Backend;
    QString name() const override { return QStringLiteral("ufw"); }
    bool arm(const QStringList &endpointIps, const QStringList &uplinks, QString *err) override;
    bool disarm(QString *err) override;
    bool isArmed() override;
    bool supportsCgroup() const override { return false; }
    bool applyAppRules(const AppRuleSpec &, QString *err) override
    { if (err) *err = QStringLiteral("ufw cannot match cgroups; use iptables, nftables or firewalld for the cgroup methods"); return false; }
    bool removeAppRules(QString *) override { return true; }
    QString appRulesTag() override { return QString(); }
    void tunnelChanged(const QString &dev) override;
private:
    CmdResult ufw(const QStringList &args) const { return m_r.run(QStringList{QStringLiteral("ufw")} + args); }
    bool allowTunnel(const QString &dev, QString *err) const;
    static const QString kTag;
};
