#pragma once
#include <QString>
#include <QStringList>

namespace NetInfo {
    QString tunnelDevice(const QString &prefix);                  // first /sys/class/net/<prefix>* device
    QStringList defaultRouteDevices(const QString &tunnelPrefix); // `ip route show default` devs, tunnel excluded
    QStringList splitTerse(const QString &line);                  // one line of `nmcli -t` output -> fields
}
