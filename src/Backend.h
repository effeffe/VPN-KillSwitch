#pragma once
#include "Config.h"
#include "Runner.h"
#include <memory>

// Firewall half of the cgroup per-app methods (see Namespace::ruleSpec).
struct AppRuleSpec {
    QString cgroupPath;   // relative to /sys/fs/cgroup, e.g. vpnks.slice; matches it and all below
    bool split = false;   // also mark the traffic and NAT it onto the namespace link
    QString mark;         // fwmark the helper's policy routing looks for
    QString hostIf;       // host side of the namespace link
    QString tag;          // rule comment "vpnks:apps:<fingerprint of spec + settings>"
};

// One implementation per firewall. All produce the same policy:
//   accept local -> accept LAN -> accept VPN endpoints -> accept tunnel -> REJECT
// and tag every rule so disarm can find them regardless of current settings.
class Backend {
public:
    Backend(const Runner &r, const GlobalConfig &c) : m_r(r), m_c(c) {}
    virtual ~Backend() = default;

    virtual QString name() const = 0;
    virtual bool arm(const QStringList &endpointIps, const QStringList &uplinks, QString *err) = 0;
    virtual bool disarm(QString *err) = 0;
    virtual bool isArmed() = 0;

    // Rules for apps in the vpnks slice; independent of arm/disarm.
    virtual bool supportsCgroup() const { return true; }
    virtual bool applyAppRules(const AppRuleSpec &s, QString *err) = 0;   // replaces any previous set
    virtual bool removeAppRules(QString *err) = 0;
    virtual QString appRulesTag() = 0;                                   // tag of the installed set, or empty

    // Called when the tunnel device name changes while armed (only ufw needs it).
    virtual void tunnelChanged(const QString &dev) { Q_UNUSED(dev); }

    static std::unique_ptr<Backend> create(const Runner &r, const GlobalConfig &c);

protected:
    static constexpr const char *kGlobalTag = "vpnks:global";
    static constexpr const char *kAppsTag = "vpnks:apps";
    static QString findAppsTag(const QString &text);
    const Runner &m_r;
    const GlobalConfig &m_c;
};
