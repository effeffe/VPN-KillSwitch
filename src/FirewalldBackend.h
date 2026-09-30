#pragma once
#include "Backend.h"
#include <QList>
#include <functional>

class FirewalldBackend : public Backend {
public:
    using Backend::Backend;
    QString name() const override { return QStringLiteral("firewalld"); }
    bool arm(const QStringList &endpointIps, const QStringList &uplinks, QString *err) override;
    bool disarm(QString *err) override;
    bool isArmed() override;
    bool applyAppRules(const AppRuleSpec &s, QString *err) override;
    bool removeAppRules(QString *err) override;
    QString appRulesTag() override;
private:
    QList<QStringList> globalRules(const QStringList &eps, const QStringList &up) const;
    QList<QStringList> appRules(const AppRuleSpec &s) const;
    // makes the runtime and permanent rules containing `tag` exactly `rules`, without a gap
    bool sync(const QList<QStringList> &rules, const QString &tag, QString *err) const;
    bool removeWhere(const std::function<bool(const QString &)> &match, QString *err) const;
    bool removeTagged(const QString &tag, QString *err) const
    { return removeWhere([&tag](const QString &l) { return l.contains(tag); }, err); }
    void removeLegacyAppRules() const;
    bool hasTag(const QString &tag) const;
    CmdResult fw(const QStringList &args) const { return m_r.run(QStringList{QStringLiteral("firewall-cmd")} + args, false); }
};
