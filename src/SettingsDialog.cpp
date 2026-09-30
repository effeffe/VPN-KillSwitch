#include "SettingsDialog.h"
#include "NetInfo.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPushButton>
#include <QVBoxLayout>

static QStringList csv(const QString &s)
{
    QStringList out;
    for (const QString &x : s.split(QLatin1Char(','), Qt::SkipEmptyParts)) if (!x.trimmed().isEmpty()) out << x.trimmed();
    return out;
}

SettingsDialog::SettingsDialog(GlobalConfig c, QWidget *parent) : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Killswitch settings"));
    auto *form = new QFormLayout;

    m_backend = new QComboBox(this);
    m_backend->addItems({QStringLiteral("firewalld"), QStringLiteral("iptables"), QStringLiteral("nftables"), QStringLiteral("ufw")});
    m_backend->setCurrentText(c.backend);
    form->addRow(QStringLiteral("Firewall backend"), m_backend);

    m_elev = new QComboBox(this);
    m_elev->addItems({QStringLiteral("pkexec"), QStringLiteral("sudo"), QStringLiteral("none")});
    m_elev->setCurrentText(c.elevation);
    form->addRow(QStringLiteral("Privilege escalation (not used for firewalld)"), m_elev);

    m_conn = new QComboBox(this);
    m_conn->addItem(QStringLiteral("Any IPsec tunnel (interface prefix below)"));
    {
        QProcess p;
        p.start(QStringLiteral("nmcli"), {QStringLiteral("-t"), QStringLiteral("-f"), QStringLiteral("NAME,UUID,TYPE"), QStringLiteral("connection"), QStringLiteral("show")});
        if (p.waitForFinished(5000) && p.exitCode() == 0) {
            for (const QString &l : QString::fromUtf8(p.readAllStandardOutput()).split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
                const QStringList f = NetInfo::splitTerse(l);
                if (f.size() < 3 || (f[2] != QLatin1String("vpn") && f[2] != QLatin1String("wireguard"))) continue;
                const bool wg = f[2] == QLatin1String("wireguard");
                m_conn->addItem(f[0] + (wg ? QStringLiteral(" (WireGuard)") : QStringLiteral(" (IPsec)")), QStringList{f[1], f[0], f[2]});
            }
        }
    }
    if (!c.fullTunnelUuid.isEmpty()) {
        int i = 1;
        while (i < m_conn->count() && m_conn->itemData(i).toStringList().value(0) != c.fullTunnelUuid) ++i;
        if (i == m_conn->count())   // no longer in NetworkManager: keep it selectable
            m_conn->addItem(c.fullTunnelName + QStringLiteral(" (missing)"),
                            QStringList{c.fullTunnelUuid, c.fullTunnelName, c.wireguardTunnel() ? QStringLiteral("wireguard") : QStringLiteral("vpn"), c.fullTunnelIface});
        m_conn->setCurrentIndex(i);
    }
    m_conn->setToolTip(QStringLiteral("The connection that serves as full tunnel for the killswitch and the per-app killswitch.\n"
                                      "IPsec (strongSwan): its nm-xfrm interface; WireGuard: its interface name.\n"
                                      "The VPN server it connects to is allowed automatically while it is up."));
    form->addRow(QStringLiteral("Full-tunnel connection"), m_conn);

    m_tunnel = new QLineEdit(c.tunnelPrefix, this);
    form->addRow(QStringLiteral("IPsec tunnel interface prefix"), m_tunnel);
    connect(m_conn, &QComboBox::currentIndexChanged, this, [this](int) {
        m_tunnel->setEnabled(m_conn->currentData().toStringList().value(2) != QLatin1String("wireguard"));
    });
    m_tunnel->setEnabled(!c.wireguardTunnel());
    m_phys = new QLineEdit(c.physIf, this);
    m_phys->setPlaceholderText(QStringLiteral("empty = auto: every `ip route show default` device (re-armed when it changes)"));
    form->addRow(QStringLiteral("Uplink interface(s)"), m_phys);
    m_lan = new QLineEdit(c.lan.join(QStringLiteral(", ")), this);
    form->addRow(QStringLiteral("LAN CIDRs (comma-separated)"), m_lan);

    auto *epRow = new QHBoxLayout;
    m_eps = new QLineEdit(c.endpoints.join(QStringLiteral(", ")), this);
    m_eps->setPlaceholderText(QStringLiteral("de-dd.jumptoserver.com, 146.70.118.178 — resolved at arm time"));
    auto *imp = new QPushButton(QStringLiteral("Import from NM…"), this);
    connect(imp, &QPushButton::clicked, this, &SettingsDialog::importFromNetworkManager);
    epRow->addWidget(m_eps, 1); epRow->addWidget(imp);
    form->addRow(QStringLiteral("VPN endpoints"), epRow);

    m_dns = new QLineEdit(c.dns.join(QStringLiteral(", ")), this);
    m_dns->setPlaceholderText(QStringLiteral("optional resolvers allowed on :53 outside the tunnel (leave empty to fail closed)"));
    form->addRow(QStringLiteral("DNS servers"), m_dns);

    m_block6 = new QCheckBox(QStringLiteral("Reject all outbound IPv6 (recommended)"), this);
    m_block6->setChecked(c.blockIpv6);
    form->addRow(QString(), m_block6);

    auto *note = new QLabel(QStringLiteral("<small>Pick the backend that actually manages your firewall — running iptables rules next to firewalld, or two backends at once, will conflict.</small>"), this);
    note->setWordWrap(true);

    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(bb, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, this, &QDialog::reject);

    auto *lay = new QVBoxLayout(this);
    lay->addLayout(form); lay->addWidget(note); lay->addWidget(bb);
    resize(640, sizeHint().height());
}

GlobalConfig SettingsDialog::config() const
{
    GlobalConfig c;
    c.backend = m_backend->currentText();
    c.elevation = m_elev->currentText();
    c.tunnelPrefix = m_tunnel->text().trimmed();
    const QStringList conn = m_conn->currentData().toStringList();   // uuid, name, type[, iface]
    if (!conn.isEmpty()) {
        c.fullTunnelUuid = conn.value(0);
        c.fullTunnelName = conn.value(1);
        if (conn.value(2) == QLatin1String("wireguard")) {
            c.fullTunnelIface = conn.value(3);
            QProcess p;
            p.start(QStringLiteral("nmcli"), {QStringLiteral("-g"), QStringLiteral("connection.interface-name"), QStringLiteral("connection"),
                                              QStringLiteral("show"), QStringLiteral("uuid"), c.fullTunnelUuid});
            if (p.waitForFinished(5000) && p.exitCode() == 0) {
                const QString iface = QString::fromUtf8(p.readAllStandardOutput()).trimmed();
                if (!iface.isEmpty()) c.fullTunnelIface = iface;
            }
        }
    }
    c.physIf = m_phys->text().trimmed();
    c.lan = csv(m_lan->text());
    c.endpoints = csv(m_eps->text());
    c.dns = csv(m_dns->text());
    c.blockIpv6 = m_block6->isChecked();
    return c;
}

void SettingsDialog::importFromNetworkManager()
{
    QProcess p;
    p.start(QStringLiteral("nmcli"), {QStringLiteral("-g"), QStringLiteral("NAME,TYPE"), QStringLiteral("connection"), QStringLiteral("show")});
    if (!p.waitForFinished(5000) || p.exitCode() != 0) { QMessageBox::warning(this, QStringLiteral("nmcli"), QStringLiteral("nmcli not available")); return; }
    QStringList vpns;
    for (const QString &l : QString::fromUtf8(p.readAllStandardOutput()).split(QLatin1Char('\n'), Qt::SkipEmptyParts)) {
        const QStringList f = l.split(QLatin1Char(':'));
        if (f.size() >= 2 && f[1] == QLatin1String("vpn")) vpns << f[0];
    }
    if (vpns.isEmpty()) { QMessageBox::information(this, QStringLiteral("nmcli"), QStringLiteral("No VPN connections found")); return; }
    bool ok = false;
    const QString name = QInputDialog::getItem(this, QStringLiteral("Import"), QStringLiteral("VPN connection"), vpns, 0, false, &ok);
    if (!ok) return;
    QProcess q;
    q.start(QStringLiteral("nmcli"), {QStringLiteral("-g"), QStringLiteral("vpn.data"), QStringLiteral("connection"), QStringLiteral("show"), name});
    q.waitForFinished(5000);
    QStringList found;
    for (const QString &kv : QString::fromUtf8(q.readAllStandardOutput()).trimmed().split(QStringLiteral(", "), Qt::SkipEmptyParts)) {
        const int eq = kv.indexOf(QLatin1Char('='));
        if (eq < 0) continue;
        const QString k = kv.left(eq).trimmed();
        if (k == QLatin1String("address") || k == QLatin1String("remote") || k == QLatin1String("gateway") || k == QLatin1String("server"))
            found << kv.mid(eq + 1).trimmed();
    }
    if (found.isEmpty()) { QMessageBox::information(this, QStringLiteral("Import"), QStringLiteral("No endpoint key found in vpn.data")); return; }
    QStringList cur = csv(m_eps->text());
    for (const QString &f : found) if (!cur.contains(f)) cur << f;
    m_eps->setText(cur.join(QStringLiteral(", ")));
}
