#pragma once
#include <QString>

// Mirror of /etc/vpnks/helper.conf, which the root helper and the NetworkManager
// dispatcher hook read. The GUI only needs the names and the host-only link addresses.
struct HelperConfig {
    QString ns       = QStringLiteral("vpnks");
    QString tunnel   = QStringLiteral("vpnks0");
    QString hostAddr = QStringLiteral("10.99.0.1/30");
    QString nsAddr   = QStringLiteral("10.99.0.2/30");
    QString hostIf   = QStringLiteral("vpnks-h");
    QString mode     = QStringLiteral("netns");         // netns | cgroup-split | cgroup-killswitch
    QString slice    = QStringLiteral("vpnks.slice");
    QString mark     = QStringLiteral("0x766b");

    static QString defaultPath() { return QStringLiteral("/etc/vpnks/helper.conf"); }
    static bool installed();
    static HelperConfig load(const QString &path = defaultPath());

    QString hostIp() const { return hostAddr.section(QLatin1Char('/'), 0, 0); }
    QString nsIp() const   { return nsAddr.section(QLatin1Char('/'), 0, 0); }
    QString hostNetwork() const;   // e.g. 10.99.0.0/30
};
