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
    QStringList resolvedEndpoints(QString *err = nullptr) const;   // configured endpoints + live peers
    // Re-reads the live IPsec/WireGuard peers (vpnks-helper peers) while the full tunnel is up;
    // the last known set is kept (and remembered across restarts) while it is down. True when
    // they changed, i.e. the armed killswitch and the cgroup rules need updating.
    bool updatePeers();
    QStringList peers() const { return m_peers; }
    QStringList uplinks() const { return config.uplinks(); }
private:
    std::unique_ptr<Backend> m_b;
    QStringList m_peers;
};
