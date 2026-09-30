#pragma once
#include "AppStore.h"
#include "Backend.h"
#include "HelperConfig.h"
#include "Killswitch.h"
#include "Runner.h"
#include <QHash>
#include <QString>

struct NsState {
    bool helperInstalled = false;   // /usr/lib/vpnks/vpnks-helper present
    bool nsPresent = false;         // /run/netns/<ns> exists
    bool tunnelAttached = false;    // the split profile's XFRM interface is inside the namespace
    bool cgroupRouting = false;     // cgroup split: marked traffic is routed into the namespace
    QString vip, dns, connectionId;
};

// Per-app VPN. The split profile's XFRM interface is moved into the network namespace by the
// NetworkManager dispatcher hook on vpn-up. Apps then either run inside that namespace
// (Mode::Netns), or in the system slice vpnks.slice where firewall rules match them by
// cgroup: CgroupSplit marks their traffic and the helper routes it through the namespace into
// the tunnel; CgroupKillswitch only lets them out through the full tunnel.
// Root work happens in /usr/lib/vpnks/vpnks-helper (via pkexec); firewall rules come from the
// killswitch backend. Everything read here is world-readable, so polling needs no privileges.
class Namespace {
public:
    static QString helperPath() { return QStringLiteral("/usr/lib/vpnks/vpnks-helper"); }

    enum class Mode { Netns, CgroupSplit, CgroupKillswitch };
    static QString modeKey(Mode m);
    static Mode modeFromKey(const QString &k);
    static QString modeLabel(Mode m);
    Mode mode() const { return modeFromKey(cfg.mode); }
    bool isCgroup() const { return mode() != Mode::Netns; }

    explicit Namespace(const Runner &r) : m_r(r) { reload(); }
    void reload() { cfg = HelperConfig::load(); }
    HelperConfig cfg;

    NsState state() const;
    bool setup(QString *err) const;
    bool teardown(bool force, QString *err) const;
    bool setMode(Mode m, bool force, QString *err) const;   // helper set-mode (routing, slice, config)
    bool stopApps(QString *err) const;

    // Firewall rules for the cgroup methods, fingerprinted with every setting they depend on.
    AppRuleSpec ruleSpec(const GlobalConfig &c) const;
    // Makes sure the rules match ruleSpec(). With apps still running under older rules those are
    // kept (they still confine the apps) and *warn says so. False = do not launch.
    bool ensureAppRules(Killswitch &ks, QString *err, QString *warn = nullptr) const;
    int sliceProcessCount() const;                          // all processes in vpnks.slice

    // Starts `app` inside the namespace as the current user (systemd-run --user -> pkexec helper).
    bool launch(const AppEntry &app, QString *err) const;
    // app id -> this user's processes in the namespace or the slice (by VPNKS_APP in their env)
    QHash<QString, int> runningCounts() const;

    // ~/.local/share/applications/vpnks-<id>.desktop running `vpnks --launch <id>`
    bool writeDesktopEntry(const AppEntry &app, QString *path, QString *err) const;
    static void removeDesktopEntry(const QString &id);
    static QString desktopEntryPath(const QString &id);

    static QStringList sessionEnvArgs();   // whitelisted session environment as --env KEY=VALUE
private:
    bool helper(const QStringList &args, QString *err) const;
    const Runner &m_r;
};
