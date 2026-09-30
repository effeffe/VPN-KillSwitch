#pragma once
#include <QString>
#include <QStringList>

struct GlobalConfig {
    QString backend   = QStringLiteral("firewalld"); // firewalld | iptables | nftables | ufw
    QString elevation = QStringLiteral("pkexec");    // pkexec | sudo | none  (ignored for firewalld)
    QString tunnelPrefix = QStringLiteral("nm-xfrm"); // iptables: prefix+   nft: "prefix*"
    QString physIf;                                   // comma list; empty = auto from `ip route show default`
    QStringList uplinks() const;                      // resolved list (physIf or default-route devices)
    QStringList lan = {QStringLiteral("192.168.0.0/16")};
    QStringList allowedCidrs() const;                 // lan + the namespace host-only link (if installed)
    QString hostLinkIf() const;                       // host side of that link, empty if not installed
    QStringList endpoints;                            // VPN server IPs or hostnames (resolved at arm time)
    QStringList dns;                                  // optional resolvers allowed on :53 outside the tunnel
    bool blockIpv6 = true;                            // reject all outbound v6 (even via tunnel)

    void load();
    void save() const;
    QString tunnelIpt() const { return tunnelPrefix + QLatin1Char('+'); }
    QString tunnelNft() const { return tunnelPrefix + QLatin1Char('*'); }
};
