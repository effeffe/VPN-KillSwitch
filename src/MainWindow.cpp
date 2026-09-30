#include "MainWindow.h"
#include "NetInfo.h"
#include "SettingsDialog.h"
#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStatusBar>
#include <QTableWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QWindow>

enum Col { ColName, ColCommand, ColRunning, ColCount };

static QIcon makeIcon(bool armed, bool tunnelUp, bool nsAttached)
{
    QPixmap px(32, 32);
    px.fill(Qt::transparent);
    QPainter p(&px);
    p.setRenderHint(QPainter::Antialiasing);
    p.setPen(Qt::NoPen);
    p.setBrush(armed ? (tunnelUp ? QColor(0x2e, 0xa0, 0x43) : QColor(0xd9, 0x8c, 0x00)) : QColor(0x88, 0x88, 0x88));
    p.drawEllipse(2, 2, 28, 28);
    if (armed) { p.setBrush(Qt::white); p.drawRect(12, 8, 8, 16); }   // "lock bar"
    if (nsAttached) {                                                // split tunnel active
        p.setBrush(Qt::white); p.drawEllipse(19, 19, 13, 13);
        p.setBrush(QColor(0x1f, 0x6f, 0xeb)); p.drawEllipse(21, 21, 9, 9);
    }
    return QIcon(px);
}

// nmcli -t output: fields separated by ':', with ':' and '\' inside values backslash-escaped
static QStringList splitTerse(const QString &line)
{
    QStringList out;
    QString cur;
    bool esc = false;
    for (const QChar ch : line) {
        if (esc) { cur += ch; esc = false; }
        else if (ch == QLatin1Char('\\')) esc = true;
        else if (ch == QLatin1Char(':')) { out << cur; cur.clear(); }
        else cur += ch;
    }
    out << cur;
    return out;
}

MainWindow::MainWindow(Killswitch &ks, Namespace &ns, bool startHidden, QWidget *parent)
    : QMainWindow(parent), m_ks(ks), m_ns(ns), m_startHidden(startHidden)
{
    setWindowTitle(QStringLiteral("VPN killswitch"));
    resize(860, 600);

    // --- global arm/disarm panel (full tunnel) ---
    auto *top = new QWidget(this);
    auto *topLay = new QHBoxLayout(top);
    m_armBtn = new QPushButton(top);
    m_armBtn->setCheckable(true);
    m_armBtn->setMinimumHeight(48);
    m_armBtn->setStyleSheet(QStringLiteral("QPushButton{font-size:15px;font-weight:bold;padding:6px 24px;} QPushButton:checked{background:#2ea043;color:white;}"));
    connect(m_armBtn, &QPushButton::clicked, this, &MainWindow::toggleArmed);
    m_armLabel = new QLabel(top);
    m_armLabel->setWordWrap(true);
    auto *settings = new QPushButton(QStringLiteral("Settings…"), top);
    connect(settings, &QPushButton::clicked, this, &MainWindow::openSettings);
    auto *refreshBtn = new QPushButton(QStringLiteral("Refresh"), top);
    connect(refreshBtn, &QPushButton::clicked, this, &MainWindow::refresh);
    topLay->addWidget(m_armBtn); topLay->addWidget(m_armLabel, 1); topLay->addWidget(settings); topLay->addWidget(refreshBtn);

    // --- VPN namespace (split tunnel) ---
    auto *nsBox = new QGroupBox(QStringLiteral("Per-app VPN — only these apps use the VPN"), this);
    auto *nsLay = new QVBoxLayout(nsBox);
    auto *methodRow = new QHBoxLayout;
    m_methodCombo = new QComboBox(nsBox);
    for (const auto m : {Namespace::Mode::Netns, Namespace::Mode::CgroupSplit, Namespace::Mode::CgroupKillswitch})
        m_methodCombo->addItem(Namespace::modeLabel(m), int(m));
    m_methodCombo->setToolTip(QStringLiteral(
        "Network namespace: apps run in their own network stack whose only exit is the split tunnel (fail-closed by construction).\n"
        "cgroup — split tunnel: apps stay in the normal network stack (localhost, LAN discovery work); firewall rules mark their "
        "traffic and it is routed through the namespace into the split tunnel.\n"
        "cgroup — killswitch only: apps may only leave through the full tunnel; use with your normal profile."));
    connect(m_methodCombo, &QComboBox::activated, this, &MainWindow::changeMethod);
    methodRow->addWidget(new QLabel(QStringLiteral("Method:"), nsBox));
    methodRow->addWidget(m_methodCombo);
    methodRow->addStretch();
    m_nsLabel = new QLabel(nsBox);
    m_nsLabel->setWordWrap(true);
    m_nsLabel->setTextFormat(Qt::RichText);
    m_nsLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto *nsRow = new QHBoxLayout;
    auto *profileBtn = new QPushButton(QStringLiteral("Create split profile…"), nsBox);
    profileBtn->setToolTip(QStringLiteral("Copies a NetworkManager VPN connection so that, when connected, its tunnel serves only the namespace."));
    m_setupBtn = new QPushButton(QStringLiteral("Set up namespace"), nsBox);
    m_teardownBtn = new QPushButton(QStringLiteral("Tear down"), nsBox);
    connect(profileBtn, &QPushButton::clicked, this, &MainWindow::createSplitProfile);
    connect(m_setupBtn, &QPushButton::clicked, this, &MainWindow::nsSetup);
    connect(m_teardownBtn, &QPushButton::clicked, this, &MainWindow::nsTeardown);
    nsRow->addWidget(profileBtn); nsRow->addWidget(m_setupBtn); nsRow->addWidget(m_teardownBtn); nsRow->addStretch();

    m_table = new QTableWidget(0, ColCount, nsBox);
    m_table->setHorizontalHeaderLabels({QStringLiteral("App"), QStringLiteral("Command"), QStringLiteral("In namespace")});
    m_table->horizontalHeader()->setSectionResizeMode(ColCommand, QHeaderView::Stretch);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setToolTip(QStringLiteral("Double-click to launch inside the VPN namespace"));
    connect(m_table, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        if (row >= 0 && row < m_store.apps.size()) launchApp(m_store.apps[row]);
    });

    auto *appRow = new QHBoxLayout;
    auto *add = new QPushButton(QStringLiteral("Add…"), nsBox);
    auto *rem = new QPushButton(QStringLiteral("Remove"), nsBox);
    auto *launch = new QPushButton(QStringLiteral("Launch"), nsBox);
    auto *menuBtn = new QPushButton(QStringLiteral("Add to app menu"), nsBox);
    menuBtn->setToolTip(QStringLiteral("Creates an \"<App> (VPN)\" launcher in the application menu"));
    connect(add, &QPushButton::clicked, this, &MainWindow::addApp);
    connect(rem, &QPushButton::clicked, this, &MainWindow::removeApp);
    connect(launch, &QPushButton::clicked, this, &MainWindow::launchSelected);
    connect(menuBtn, &QPushButton::clicked, this, &MainWindow::addToAppMenu);
    appRow->addWidget(add); appRow->addWidget(rem); appRow->addWidget(launch); appRow->addWidget(menuBtn); appRow->addStretch();

    nsLay->addLayout(methodRow);
    nsLay->addWidget(m_nsLabel);
    nsLay->addLayout(nsRow);
    nsLay->addWidget(m_table);
    nsLay->addLayout(appRow);

    // --- command log ---
    m_log = new QPlainTextEdit(this);
    m_log->setReadOnly(true);
    m_log->setMaximumBlockCount(500);
    m_log->setPlaceholderText(QStringLiteral("Commands executed by vpnks appear here."));
    m_ks.runner.logger = [this](const QString &s) { m_log->appendPlainText(s); };

    auto *split = new QSplitter(Qt::Vertical, this);
    split->addWidget(nsBox);
    split->addWidget(m_log);
    split->setStretchFactor(0, 3); split->setStretchFactor(1, 1);

    auto *central = new QWidget(this);
    auto *lay = new QVBoxLayout(central);
    lay->addWidget(top); lay->addWidget(split, 1);
    setCentralWidget(central);

    m_status = new QLabel(this);
    statusBar()->addWidget(m_status, 1);

    m_trayMenu = new QMenu(this);
    setupTray();

    m_liveTimer = new QTimer(this);
    connect(m_liveTimer, &QTimer::timeout, this, &MainWindow::refreshLive);
    m_liveTimer->start(3000);

    m_store.load();
    refresh();
}

void MainWindow::closeEvent(QCloseEvent *e)
{
    if (m_tray && m_tray->isVisible()) { hide(); e->ignore(); }
    else { e->accept(); qApp->quit(); }
}

void MainWindow::showArmed(bool armed)
{
    m_armed = armed;
    m_armBtn->blockSignals(true);
    m_armBtn->setChecked(armed);
    m_armBtn->setText(armed ? QStringLiteral("ARMED — click to disarm") : QStringLiteral("DISARMED — click to arm"));
    m_armBtn->blockSignals(false);
    m_armLabel->setText(armed
        ? QStringLiteral("Full tunnel: all outbound traffic is confined to the tunnel (plus LAN and the VPN endpoint). This stays in place across VPN disconnects until you disarm it.")
        : QStringLiteral("Full tunnel killswitch off. Arm it to fail closed whenever the tunnel is down. (Leave it off for split tunnelling.)"));
}

void MainWindow::toggleArmed(bool on)
{
    if (on && m_ks.config.endpoints.isEmpty()) {
        if (QMessageBox::question(this, QStringLiteral("No VPN endpoint configured"),
                QStringLiteral("Without an allowed endpoint the tunnel cannot re-establish once armed. Arm anyway?")) != QMessageBox::Yes) { showArmed(m_armed); return; }
    }
    QString err;
    const bool ok = on ? m_ks.arm(&err) : m_ks.disarm(&err);
    if (!ok) QMessageBox::warning(this, m_ks.backendName(), QStringLiteral("Could not %1:\n%2").arg(on ? QStringLiteral("arm") : QStringLiteral("disarm"), err));
    else if (!err.isEmpty()) m_log->appendPlainText(QStringLiteral("warning: ") + err.trimmed());
    showArmed(m_ks.isArmed());
    updateNsStatus();
    rebuildTrayMenu();
}

void MainWindow::openSettings()
{
    SettingsDialog d(m_ks.config, this);
    if (d.exec() != QDialog::Accepted) return;
    const bool wasArmed = m_ks.isArmed();
    const bool backendChanges = d.config().backend != m_ks.config.backend;
    if (wasArmed && backendChanges) {
        QMessageBox::warning(this, QStringLiteral("Backend change"), QStringLiteral("Disarm with the current backend before switching backends, otherwise the old rules stay behind."));
        return;
    }
    if (backendChanges && m_ns.isCgroup()) {
        if (m_ns.sliceProcessCount() > 0) {
            QMessageBox::warning(this, QStringLiteral("Backend change"), QStringLiteral("Quit the apps running under the cgroup method first: their firewall rules have to move to the new backend."));
            return;
        }
        QString err;
        if (!m_ks.removeAppRules(&err)) m_log->appendPlainText(QStringLiteral("warning: removing cgroup rules: ") + err);
    }
    m_ks.config = d.config();
    m_ks.config.save();
    m_ks.reload();
    if (wasArmed) { QString err; if (!m_ks.arm(&err)) QMessageBox::warning(this, QStringLiteral("Re-arm"), err); }
    refresh();
}

void MainWindow::createSplitProfile()
{
    QProcess p;
    p.start(QStringLiteral("nmcli"), {QStringLiteral("-t"), QStringLiteral("-f"), QStringLiteral("NAME,UUID,TYPE"), QStringLiteral("connection"), QStringLiteral("show")});
    if (!p.waitForFinished(8000) || p.exitCode() != 0) {
        QMessageBox::warning(this, QStringLiteral("nmcli"), QStringLiteral("Could not list NetworkManager connections:\n%1").arg(QString::fromUtf8(p.readAllStandardError())));
        return;
    }
    QStringList vpnNames, vpnUuids, allNames;
    const QStringList lines = QString::fromUtf8(p.readAllStandardOutput()).split(QLatin1Char('\n'), Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        const QStringList f = splitTerse(line);
        if (f.size() < 3) continue;
        allNames << f[0];
        if (f[2] == QLatin1String("vpn")) { vpnNames << f[0]; vpnUuids << f[1]; }
    }
    if (vpnNames.isEmpty()) { QMessageBox::information(this, QStringLiteral("Create split profile"), QStringLiteral("No VPN connections found in NetworkManager.")); return; }

    bool ok = false;
    const QString pick = QInputDialog::getItem(this, QStringLiteral("Create split profile"), QStringLiteral("Copy which VPN connection?"), vpnNames, 0, false, &ok);
    if (!ok) return;
    const int idx = vpnNames.indexOf(pick);
    const QString newName = QInputDialog::getText(this, QStringLiteral("Create split profile"), QStringLiteral("Name of the split-tunnel copy:"),
                                                  QLineEdit::Normal, pick + QStringLiteral(" (split)"), &ok).trimmed();
    if (!ok || newName.isEmpty()) return;
    if (allNames.contains(newName)) { QMessageBox::warning(this, QStringLiteral("Create split profile"), QStringLiteral("A connection called “%1” already exists.").arg(newName)); return; }

    CmdResult r = m_ks.runner.run({QStringLiteral("nmcli"), QStringLiteral("connection"), QStringLiteral("clone"), vpnUuids[idx], newName}, false);
    if (r.ok()) {
        r = m_ks.runner.run({QStringLiteral("nmcli"), QStringLiteral("connection"), QStringLiteral("modify"), QStringLiteral("id"), newName,
                             QStringLiteral("connection.interface-name"), m_ns.cfg.tunnel,
                             QStringLiteral("ipv4.never-default"), QStringLiteral("yes"),
                             QStringLiteral("ipv6.never-default"), QStringLiteral("yes")}, false);
    }
    if (!r.ok()) { QMessageBox::warning(this, QStringLiteral("nmcli"), r.err.isEmpty() ? QStringLiteral("nmcli failed") : r.err); return; }
    QMessageBox::information(this, QStringLiteral("Split profile created"),
        QStringLiteral("“%1” is a copy of “%2” whose tunnel (%3) is handed to the VPN namespace.\n\n"
                       "Connect “%1” from the NetworkManager applet for split tunnelling: your system keeps its normal "
                       "connection and only apps launched from vpnks use the VPN.\nConnect “%2” as before for a full tunnel.")
            .arg(newName, pick, m_ns.cfg.tunnel));
}

void MainWindow::changeMethod(int index)
{
    const Namespace::Mode cur = m_ns.mode();
    const auto want = Namespace::Mode(m_methodCombo->itemData(index).toInt());
    auto revert = [this, cur] { QSignalBlocker b(m_methodCombo); m_methodCombo->setCurrentIndex(m_methodCombo->findData(int(cur))); };
    if (want == cur) return;
    if (!m_nsState.helperInstalled) {
        QMessageBox::warning(this, QStringLiteral("Per-app method"), QStringLiteral("The vpnks helper is not installed (sudo cmake --install build)."));
        revert(); return;
    }
    if (want != Namespace::Mode::Netns && !m_ks.supportsCgroup()) {
        QMessageBox::warning(this, QStringLiteral("Per-app method"),
            QStringLiteral("The %1 backend cannot match cgroups. Pick iptables, nftables or firewalld in Settings first.").arg(m_ks.backendName()));
        revert(); return;
    }
    bool force = false;
    if (cur != Namespace::Mode::Netns) {
        const int n = m_ns.sliceProcessCount();
        if (n > 0) {
            if (QMessageBox::question(this, QStringLiteral("Per-app method"),
                    QStringLiteral("%1 process(es) run under the current cgroup method. The firewall rules that confine them are about "
                                   "to change, so they have to stop first. Stop them now?").arg(n)) != QMessageBox::Yes) { revert(); return; }
            force = true;
        }
    }
    QString err;
    if (!m_ns.setMode(want, force, &err)) {
        QMessageBox::warning(this, QStringLiteral("Per-app method"), err);
        revert(); return;
    }
    m_ns.reload();
    if (want == Namespace::Mode::Netns) {
        if (!m_ks.removeAppRules(&err)) QMessageBox::warning(this, QStringLiteral("Per-app method"), QStringLiteral("Could not remove the cgroup rules:\n") + err);
    }
    if (cur == Namespace::Mode::Netns && !m_counts.isEmpty())
        m_log->appendPlainText(QStringLiteral("apps already running in the namespace stay there until you quit them"));
    refresh();
}

void MainWindow::nsSetup()
{
    QString err;
    if (!m_ns.setup(&err)) QMessageBox::warning(this, QStringLiteral("VPN namespace"), err);
    refreshLive();
}

void MainWindow::nsTeardown()
{
    int running = 0;
    for (int n : std::as_const(m_counts)) running += n;
    QString q = QStringLiteral("Remove the VPN namespace and its host-only link?");
    if (running > 0) q += QStringLiteral("\n\n%1 process(es) still run inside and will be stopped.").arg(running);
    if (m_nsState.tunnelAttached) q += QStringLiteral("\n\nThe split VPN stays connected in NetworkManager but loses its interface — disconnect it too.");
    if (QMessageBox::question(this, QStringLiteral("Tear down"), q) != QMessageBox::Yes) return;
    QString err;
    if (!m_ns.teardown(running > 0, &err)) QMessageBox::warning(this, QStringLiteral("VPN namespace"), err);
    refreshLive();
}

void MainWindow::rebuildTable()
{
    m_table->setRowCount(0);
    for (int i = 0; i < m_store.apps.size(); ++i) {
        const AppEntry &a = m_store.apps[i];
        m_table->insertRow(i);
        m_table->setItem(i, ColName,    new QTableWidgetItem(a.name));
        m_table->setItem(i, ColCommand, new QTableWidgetItem(a.command));
        m_table->setItem(i, ColRunning, new QTableWidgetItem(QStringLiteral("—")));
    }
    updateRows();
}

void MainWindow::updateRows()
{
    for (int i = 0; i < m_store.apps.size() && i < m_table->rowCount(); ++i) {
        const int n = m_counts.value(m_store.apps[i].id);
        m_table->item(i, ColRunning)->setText(n > 0 ? QStringLiteral("%1 process%2").arg(n).arg(n == 1 ? QString() : QStringLiteral("es")) : QStringLiteral("—"));
    }
}

void MainWindow::updateNsStatus()
{
    const NsState &s = m_nsState;
    const Namespace::Mode mode = m_ns.mode();
    QString t;
    if (!s.helperInstalled) {
        t = QStringLiteral("<b>Helper not installed.</b> Run <code>sudo cmake --install build</code> — it installs the root helper, "
                           "the NetworkManager hook, the systemd slice and the polkit policy.");
    } else if (mode == Namespace::Mode::Netns) {
        if (!s.nsPresent) {
            t = QStringLiteral("<b>Namespace not set up.</b> It is created automatically on the first launch or when a split profile connects.");
        } else if (s.tunnelAttached) {
            t = QStringLiteral("<b>Tunnel attached</b>%1 — apps below run inside the namespace and use the VPN (source %2, DNS %3); "
                               "everything else uses your normal connection.<br>Services inside are reachable from this desktop at <b>%4</b>.")
                    .arg(s.connectionId.isEmpty() ? QString() : QStringLiteral(" (“%1”)").arg(s.connectionId.toHtmlEscaped()),
                         s.vip.toHtmlEscaped(), s.dns.toHtmlEscaped(), m_ns.cfg.nsIp());
        } else {
            t = QStringLiteral("<b>No tunnel</b> — connect a split profile (interface <code>%1</code>) from the NetworkManager applet. "
                               "Apps in the namespace stay offline until then.").arg(m_ns.cfg.tunnel);
        }
    } else if (mode == Namespace::Mode::CgroupSplit) {
        if (s.tunnelAttached && s.cgroupRouting) {
            t = QStringLiteral("<b>Split tunnel active</b>%1 — apps below run in <code>%2</code>; their traffic is marked and routed through "
                               "the namespace into the VPN (appears as %3, DNS %4). Everything else uses your normal connection.")
                    .arg(s.connectionId.isEmpty() ? QString() : QStringLiteral(" (“%1”)").arg(s.connectionId.toHtmlEscaped()),
                         m_ns.cfg.slice, s.vip.toHtmlEscaped(), s.dns.toHtmlEscaped());
        } else {
            t = QStringLiteral("<b>No split tunnel</b> — connect a split profile (interface <code>%1</code>) from the NetworkManager applet. "
                               "Until then apps below can only leave through a full tunnel, if one is up, and are blocked otherwise.").arg(m_ns.cfg.tunnel);
        }
    } else {
        t = QStringLiteral("<b>Per-app killswitch</b> — apps below run in <code>%1</code> and may only leave through the full tunnel "
                           "(<code>%2*</code>), LAN and localhost. Use your normal profile. Full tunnel: <b>%3</b>.")
                .arg(m_ns.cfg.slice, m_ks.config.tunnelPrefix.toHtmlEscaped(), m_lastDev.isEmpty() ? QStringLiteral("down — apps are blocked") : QStringLiteral("up"));
    }
    if (s.helperInstalled && mode != Namespace::Mode::Netns) {
        if (!m_rulesWarn.isEmpty()) t += QStringLiteral("<br><span style='color:#b35900'>%1</span>").arg(m_rulesWarn.toHtmlEscaped());
        else if (!m_rulesTag.isEmpty()) t += QStringLiteral("<br>Firewall rules loaded (%1, backend %2).").arg(m_rulesTag, m_ks.backendName());
        else t += QStringLiteral("<br><span style='color:#b35900'>Firewall rules not loaded — apps won't be launched.</span>");
    }
    if (m_armed && s.tunnelAttached && mode != Namespace::Mode::CgroupKillswitch)
        t += QStringLiteral("<br><span style='color:#b35900'>The full-tunnel killswitch is armed, so the host itself is offline apart from LAN — disarm it for split tunnelling.</span>");
    m_nsLabel->setText(t);
    const bool usesNs = mode != Namespace::Mode::CgroupKillswitch;
    m_setupBtn->setEnabled(s.helperInstalled && usesNs);
    m_teardownBtn->setEnabled(s.helperInstalled && s.nsPresent && usesNs);
}

void MainWindow::refreshRules()
{
    // Queries (and for iptables/nftables: pkexec) the firewall, so only on refresh, launch and changes.
    m_rulesTag.clear();
    m_rulesWarn.clear();
    if (!m_ns.isCgroup() || !m_nsState.helperInstalled) return;
    QString err, warn;
    if (!m_ns.ensureAppRules(m_ks, &err, &warn)) m_rulesWarn = err;
    else m_rulesWarn = warn;
    m_rulesTag = m_ks.appRulesTag();
}

void MainWindow::refresh()
{
    m_ns.reload();
    {
        QSignalBlocker b(m_methodCombo);
        m_methodCombo->setCurrentIndex(m_methodCombo->findData(int(m_ns.mode())));
    }
    showArmed(m_ks.isArmed());
    rebuildTable();
    m_nsState = m_ns.state();
    refreshRules();
    refreshLive();
}

void MainWindow::refreshLive()
{
    const QString dev = NetInfo::tunnelDevice(m_ks.config.tunnelPrefix);
    const bool up = !dev.isEmpty();
    if (dev != m_lastDev) { m_lastDev = dev; if (up && m_armed) m_ks.tunnelChanged(dev); }
    const QStringList ul = m_ks.uplinks();
    if (ul != m_lastUplinks) {
        const bool first = m_lastUplinks.isEmpty() && !m_armed;
        m_lastUplinks = ul;
        if (m_armed && !first && m_ks.config.physIf.trimmed().isEmpty()) {
            m_log->appendPlainText(QStringLiteral("uplinks changed -> re-arming"));
            QString err; if (!m_ks.arm(&err) && m_tray) m_tray->showMessage(QStringLiteral("Re-arm failed"), err);
        }
    }
    m_nsState = m_ns.state();
    m_counts = m_ns.runningCounts();
    updateRows();
    updateNsStatus();

    m_status->setText(QStringLiteral("backend: %1   ·   full tunnel: %2   ·   split tunnel: %3   ·   per-app: %5   ·   uplinks: %4")
        .arg(m_ks.backendName(),
             up ? QStringLiteral("UP (%1)").arg(dev) : QStringLiteral("down"),
             m_nsState.tunnelAttached ? QStringLiteral("tunnel attached") : (m_nsState.nsPresent ? QStringLiteral("no tunnel") : QStringLiteral("absent")),
             ul.isEmpty() ? QStringLiteral("(any)") : ul.join(QLatin1Char(' ')), Namespace::modeLabel(m_ns.mode())));
    if (m_tray) {
        m_tray->setIcon(makeIcon(m_armed, up, m_nsState.tunnelAttached));
        m_tray->setToolTip(QStringLiteral("Killswitch %1 · full tunnel %2 · namespace %3")
            .arg(m_armed ? QStringLiteral("armed") : QStringLiteral("disarmed"), up ? QStringLiteral("up") : QStringLiteral("down"),
                 m_nsState.tunnelAttached ? QStringLiteral("attached") : QStringLiteral("no tunnel")));
    }
    rebuildTrayMenu();
}

void MainWindow::rebuildTrayMenu()
{
    m_trayMenu->clear();
    QAction *armAct = m_trayMenu->addAction(m_armed ? QStringLiteral("Killswitch armed") : QStringLiteral("Killswitch disarmed"));
    armAct->setCheckable(true);
    armAct->setChecked(m_armed);
    connect(armAct, &QAction::triggered, this, &MainWindow::toggleArmed);
    m_trayMenu->addAction(m_lastDev.isEmpty() ? QStringLiteral("Full tunnel: down") : QStringLiteral("Full tunnel: up (%1)").arg(m_lastDev))->setEnabled(false);
    m_trayMenu->addAction(m_nsState.tunnelAttached ? QStringLiteral("Split tunnel: attached (%1)").arg(m_nsState.vip)
                                                   : QStringLiteral("Split tunnel: none"))->setEnabled(false);
    m_trayMenu->addAction(QStringLiteral("Per-app: ") + Namespace::modeLabel(m_ns.mode()))->setEnabled(false);
    if (!m_store.apps.isEmpty()) {
        m_trayMenu->addSeparator();
        QMenu *launch = m_trayMenu->addMenu(QStringLiteral("Launch in VPN"));
        for (const AppEntry &a : std::as_const(m_store.apps)) {
            const int n = m_counts.value(a.id);
            launch->addAction(n > 0 ? QStringLiteral("%1  (running)").arg(a.name) : a.name, this, [this, a] { launchApp(a); });
        }
    }
    m_trayMenu->addSeparator();
    m_trayMenu->addAction(QStringLiteral("Settings…"), this, &MainWindow::openSettings);
    m_trayMenu->addAction(QStringLiteral("Show window"), this, &MainWindow::bringToFront);
    m_trayMenu->addAction(QStringLiteral("Quit"), qApp, &QApplication::quit);
}

void MainWindow::onTrayActivated(QSystemTrayIcon::ActivationReason r)
{
    if (r == QSystemTrayIcon::Trigger) { if (isVisible()) hide(); else bringToFront(); }
}

void MainWindow::addApp()
{
    QDialog dlg(this);
    dlg.setWindowTitle(QStringLiteral("Add application"));
    auto *name = new QLineEdit(&dlg);
    auto *cmd  = new QLineEdit(&dlg);
    cmd->setPlaceholderText(QStringLiteral("e.g. transmission-qt   or   firefox -P vpn --no-remote"));
    auto *form = new QFormLayout;
    form->addRow(QStringLiteral("Name"), name);
    form->addRow(QStringLiteral("Command"), cmd);
    auto *hint = new QLabel(QStringLiteral("<small>Single-instance apps hand off to a copy that is already running outside the namespace — "
                                           "quit it first, or give the VPN copy its own profile.</small>"), &dlg);
    hint->setWordWrap(true);
    auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    auto *lay = new QVBoxLayout(&dlg);
    lay->addLayout(form); lay->addWidget(hint); lay->addWidget(bb);
    if (dlg.exec() != QDialog::Accepted || name->text().trimmed().isEmpty() || cmd->text().trimmed().isEmpty()) return;
    AppEntry e{AppStore::sanitizeId(name->text()), name->text().trimmed(), cmd->text().trimmed()};
    for (const AppEntry &x : std::as_const(m_store.apps))
        if (x.id == e.id) { QMessageBox::warning(this, QStringLiteral("Duplicate"), QStringLiteral("An app with id '%1' already exists.").arg(e.id)); return; }
    m_store.apps.push_back(e);
    m_store.save();
    refresh();
}

void MainWindow::removeApp()
{
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_store.apps.size()) return;
    Namespace::removeDesktopEntry(m_store.apps[row].id);
    m_store.apps.remove(row);
    m_store.save();
    refresh();
}

void MainWindow::launchSelected()
{
    const int row = m_table->currentRow();
    if (row >= 0 && row < m_store.apps.size()) launchApp(m_store.apps[row]);
}

void MainWindow::launchApp(const AppEntry &a)
{
    if (!m_nsState.helperInstalled) {
        QMessageBox::warning(this, QStringLiteral("Launch"), QStringLiteral("The vpnks helper is not installed (sudo cmake --install build)."));
        return;
    }
    QString err;
    if (m_ns.isCgroup()) {
        QString warn;
        const bool ok = m_ns.ensureAppRules(m_ks, &err, &warn);
        m_rulesTag = m_ks.appRulesTag();
        m_rulesWarn = ok ? warn : err;
        if (!ok) { QMessageBox::warning(this, QStringLiteral("Launch"), QStringLiteral("Not launching %1 without its firewall rules:\n%2").arg(a.name, err)); updateNsStatus(); return; }
        if (!warn.isEmpty()) m_log->appendPlainText(QStringLiteral("warning: ") + warn);
    }
    if (!m_ns.launch(a, &err)) { QMessageBox::warning(this, QStringLiteral("Launch"), err); return; }
    if (m_ns.mode() == Namespace::Mode::CgroupKillswitch) {
        if (m_lastDev.isEmpty() && m_tray)
            m_tray->showMessage(QStringLiteral("%1 started without a full tunnel").arg(a.name), QStringLiteral("It is blocked until your normal VPN profile connects."));
    } else if (!m_nsState.tunnelAttached && m_tray)
        m_tray->showMessage(QStringLiteral("%1 started without a tunnel").arg(a.name),
                            QStringLiteral("It stays offline until a split profile connects."));
    QTimer::singleShot(2500, this, &MainWindow::refreshLive);
}

void MainWindow::addToAppMenu()
{
    const int row = m_table->currentRow();
    if (row < 0 || row >= m_store.apps.size()) { QMessageBox::information(this, QStringLiteral("Add to app menu"), QStringLiteral("Select an app first.")); return; }
    QString path, err;
    if (!m_ns.writeDesktopEntry(m_store.apps[row], &path, &err)) { QMessageBox::warning(this, QStringLiteral("Add to app menu"), err); return; }
    m_log->appendPlainText(QStringLiteral("wrote %1").arg(path));
    QMessageBox::information(this, QStringLiteral("Add to app menu"),
        QStringLiteral("“%1 (VPN)” is now in the application menu. It starts the app inside the VPN namespace.").arg(m_store.apps[row].name));
}

void MainWindow::bringToFront()
{
    // On Wayland a hidden->shown window is a fresh surface and gets focus; raise()/activateWindow()
    // on an already-mapped window may be ignored by focus-stealing prevention (needs an
    // xdg-activation token the tray click doesn't carry). Toggling visibility sidesteps that.
    if (isVisible() && !isMinimized()) hide();
    showNormal();
    raise();
    activateWindow();
    if (windowHandle()) windowHandle()->requestActivate();
}

void MainWindow::setupTray()
{
    // Tray on X11 = XEmbed; on Wayland/Plasma = StatusNotifierItem over D-Bus (Qt picks the
    // right one). Some compositors (GNOME without an extension, minimal wlroots setups) have
    // neither, so never assume it: probe, and if it never appears, behave as a normal window.
    auto tryCreate = [this]() -> bool {
        if (!QSystemTrayIcon::isSystemTrayAvailable()) return false;
        m_tray = new QSystemTrayIcon(makeIcon(m_armed, !m_lastDev.isEmpty(), m_nsState.tunnelAttached), this);
        m_tray->setContextMenu(m_trayMenu);
        connect(m_tray, &QSystemTrayIcon::activated, this, &MainWindow::onTrayActivated);
        m_tray->show();
        rebuildTrayMenu();
        return true;
    };
    if (tryCreate()) return;

    // The tray host may simply not be up yet (autostart races the panel). Poll for a while.
    m_trayProbe = new QTimer(this);
    connect(m_trayProbe, &QTimer::timeout, this, [this, tryCreate] {
        if (tryCreate()) { m_trayProbe->stop(); return; }
        if (++m_trayProbes >= 15) {            // ~30 s: give up, run as a plain window
            m_trayProbe->stop();
            m_log->appendPlainText(QStringLiteral("no system tray available on this session; running as a normal window (close = quit)"));
            if (m_startHidden) show();
        }
    });
    m_trayProbe->start(2000);
    if (!m_startHidden) show();
}
