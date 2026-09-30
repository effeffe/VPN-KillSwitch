#pragma once
#include "Backend.h"
#include "Config.h"
#include "Runner.h"
#include <memory>

class Killswitch {
public:
    Killswitch();
    GlobalConfig config;
    Runner runner;

    void reload();                        // rebuild backend from config
    QString backendName() const { return m_b ? m_b->name() : QString(); }

    bool arm(QString *err = nullptr);
    bool disarm(QString *err = nullptr);
    bool isArmed();

    // firewall rules of the cgroup per-app methods
    bool supportsCgroup() const { return m_b && m_b->supportsCgroup(); }
    bool applyAppRules(const AppRuleSpec &s, QString *err = nullptr) { return m_b->applyAppRules(s, err); }
    bool removeAppRules(QString *err = nullptr) { return m_b->removeAppRules(err); }
    QString appRulesTag() { return m_b->appRulesTag(); }

    void tunnelChanged(const QString &dev) { if (m_b) m_b->tunnelChanged(dev); }
    QStringList resolvedEndpoints(QString *err = nullptr) const;
    QStringList uplinks() const { return config.uplinks(); }
private:
    std::unique_ptr<Backend> m_b;
};
