#include "Namespace.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDirIterator>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <QTextStream>
#include <sys/stat.h>
#include <unistd.h>

NsState Namespace::state() const
{
    NsState s;
    s.helperInstalled = QFileInfo(helperPath()).isExecutable();
    s.nsPresent = QFileInfo::exists(QStringLiteral("/run/netns/") + cfg.ns);
    QFile f(QStringLiteral("/run/vpnks/state"));
    if (s.nsPresent && f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QHash<QString, QString> kv;
        const QList<QByteArray> lines = f.readAll().split('\n');
        for (const QByteArray &line : lines) {
            const int eq = line.indexOf('=');
            if (eq > 0) kv.insert(QString::fromUtf8(line.left(eq)), QString::fromUtf8(line.mid(eq + 1)));
        }
        s.tunnelAttached = kv.value(QStringLiteral("tunnel")) == QLatin1String("attached");
        s.vip = kv.value(QStringLiteral("vip"));
        s.dns = kv.value(QStringLiteral("dns"));
        s.connectionId = kv.value(QStringLiteral("connection_id"));
        s.cgroupRouting = kv.value(QStringLiteral("cgroup_routing")) == QLatin1String("up");
    }
    return s;
}

QString Namespace::modeKey(Mode m)
{
    switch (m) {
    case Mode::CgroupSplit:      return QStringLiteral("cgroup-split");
    case Mode::CgroupKillswitch: return QStringLiteral("cgroup-killswitch");
    case Mode::Netns:            break;
    }
    return QStringLiteral("netns");
}

Namespace::Mode Namespace::modeFromKey(const QString &k)
{
    if (k == QLatin1String("cgroup-split")) return Mode::CgroupSplit;
    if (k == QLatin1String("cgroup-killswitch")) return Mode::CgroupKillswitch;
    return Mode::Netns;
}

QString Namespace::modeLabel(Mode m)
{
    switch (m) {
    case Mode::CgroupSplit:      return QStringLiteral("cgroup rules — split tunnel");
    case Mode::CgroupKillswitch: return QStringLiteral("cgroup rules — killswitch only");
    case Mode::Netns:            break;
    }
    return QStringLiteral("Network namespace");
}

bool Namespace::setMode(Mode m, bool force, QString *err) const
{
    QStringList a{QStringLiteral("set-mode"), modeKey(m)};
    if (force) a << QStringLiteral("--force");
    return helper(a, err);
}

bool Namespace::stopApps(QString *err) const { return helper({QStringLiteral("stop-apps")}, err); }

AppRuleSpec Namespace::ruleSpec(const GlobalConfig &c) const
{
    AppRuleSpec s;
    s.cgroupPath = cfg.slice;
    s.split = mode() == Mode::CgroupSplit;
    s.mark = cfg.mark;
    s.hostIf = cfg.hostIf;
    const QStringList parts{s.cgroupPath, s.split ? QStringLiteral("split") : QStringLiteral("killswitch"), s.mark, s.hostIf,
                            c.allowedCidrs().join(QLatin1Char(',')), c.tunnelPrefix, c.blockIpv6 ? QStringLiteral("v6off") : QStringLiteral("v6on")};
    const QByteArray h = QCryptographicHash::hash(parts.join(QLatin1Char('|')).toUtf8(), QCryptographicHash::Sha1).toHex().left(8);
    s.tag = QStringLiteral("vpnks:apps:") + QString::fromLatin1(h);
    return s;
}

int Namespace::sliceProcessCount() const
{
    int n = 0;
    QDirIterator it(QStringLiteral("/sys/fs/cgroup/") + cfg.slice, {QStringLiteral("cgroup.procs")}, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        QFile f(it.next());
        if (!f.open(QIODevice::ReadOnly)) continue;
        const QList<QByteArray> lines = f.readAll().split('\n');
        for (const QByteArray &l : lines)
            if (!l.trimmed().isEmpty()) ++n;
    }
    return n;
}

bool Namespace::ensureAppRules(Killswitch &ks, QString *err, QString *warn) const
{
    if (!isCgroup()) return true;
    if (!ks.supportsCgroup()) {
        if (err) *err = QStringLiteral("The %1 backend cannot match cgroups. Choose iptables, nftables or firewalld in Settings, "
                                       "or switch the per-app method to the network namespace.").arg(ks.backendName());
        return false;
    }
    const AppRuleSpec spec = ruleSpec(ks.config);
    const QString have = ks.appRulesTag();
    if (have == spec.tag) return true;
    if (!have.isEmpty() && sliceProcessCount() > 0) {
        if (warn) *warn = QStringLiteral("The firewall rules for VPN apps predate your current settings; quit the running VPN apps so vpnks can update them.");
        return true;   // the old rules still confine the running apps
    }
    if (ks.runner.logger) ks.runner.logger(QStringLiteral("# installing cgroup rules %1 (%2)").arg(spec.tag, modeLabel(mode())));
    return ks.applyAppRules(spec, err);
}

bool Namespace::helper(const QStringList &args, QString *err) const
{
    const CmdResult r = m_r.run(QStringList{QStringLiteral("pkexec"), helperPath()} + args, false);
    if (!r.ok() && err) *err = r.err.isEmpty() ? QStringLiteral("helper exited with status %1").arg(r.exit) : r.err;
    return r.ok();
}

bool Namespace::setup(QString *err) const { return helper({QStringLiteral("setup")}, err); }

bool Namespace::teardown(bool force, QString *err) const
{
    QStringList a{QStringLiteral("teardown")};
    if (force) a << QStringLiteral("--force");
    return helper(a, err);
}

QStringList Namespace::sessionEnvArgs()
{
    // Must stay a subset of ALLOWED_ENV in vpnks-helper (it drops anything else).
    static const QStringList keys{
        QStringLiteral("DISPLAY"), QStringLiteral("WAYLAND_DISPLAY"), QStringLiteral("XAUTHORITY"),
        QStringLiteral("XDG_RUNTIME_DIR"), QStringLiteral("DBUS_SESSION_BUS_ADDRESS"),
        QStringLiteral("XDG_SESSION_TYPE"), QStringLiteral("XDG_SESSION_DESKTOP"), QStringLiteral("XDG_CURRENT_DESKTOP"),
        QStringLiteral("DESKTOP_SESSION"), QStringLiteral("KDE_FULL_SESSION"), QStringLiteral("KDE_SESSION_VERSION"),
        QStringLiteral("QT_QPA_PLATFORM"), QStringLiteral("QT_QPA_PLATFORMTHEME"), QStringLiteral("QT_SCALE_FACTOR"),
        QStringLiteral("QT_AUTO_SCREEN_SCALE_FACTOR"), QStringLiteral("GDK_BACKEND"), QStringLiteral("GDK_SCALE"),
        QStringLiteral("GTK_THEME"), QStringLiteral("XCURSOR_THEME"), QStringLiteral("XCURSOR_SIZE"),
        QStringLiteral("MOZ_ENABLE_WAYLAND"), QStringLiteral("LANG"), QStringLiteral("LANGUAGE"), QStringLiteral("TZ"),
        QStringLiteral("PATH"), QStringLiteral("TERM"), QStringLiteral("COLORTERM"),
        QStringLiteral("XDG_DATA_DIRS"), QStringLiteral("XDG_CONFIG_DIRS"), QStringLiteral("XDG_DATA_HOME"),
        QStringLiteral("XDG_CONFIG_HOME"), QStringLiteral("XDG_CACHE_HOME"), QStringLiteral("XDG_STATE_HOME"),
        QStringLiteral("PULSE_SERVER"), QStringLiteral("PIPEWIRE_RUNTIME_DIR")};
    QStringList out;
    const QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    const QStringList names = env.keys();
    for (const QString &k : names) {
        if (!keys.contains(k) && !k.startsWith(QLatin1String("LC_"))) continue;
        const QString v = env.value(k);
        if (v.contains(QLatin1Char('\n'))) continue;
        out << QStringLiteral("--env") << k + QLatin1Char('=') + v;
    }
    return out;
}

bool Namespace::launch(const AppEntry &a, QString *err) const
{
    QStringList helperArgs{helperPath(), QStringLiteral("exec"), a.id};
    helperArgs << sessionEnvArgs() << QStringLiteral("--") << a.command;

    // A transient user service keeps the app independent of vpnks' own lifetime, gives it a
    // unit to inspect (journalctl --user -u vpnks-<id>-*), and gives pkexec a live parent.
    const QString unit = QStringLiteral("vpnks-%1-%2").arg(a.id).arg(QDateTime::currentMSecsSinceEpoch());
    QStringList args{QStringLiteral("--user"), QStringLiteral("--collect"), QStringLiteral("--quiet"),
                     QStringLiteral("--unit=") + unit, QStringLiteral("--description=vpnks: ") + a.name,
                     QStringLiteral("--"), QStringLiteral("pkexec")};
    args << helperArgs;
    if (m_r.logger) m_r.logger(QStringLiteral("$ systemd-run ") + args.join(QLatin1Char(' ')));
    if (m_r.dryRun) return true;

    QProcess p;
    p.start(QStringLiteral("systemd-run"), args);
    if (p.waitForFinished(15000) && p.exitStatus() == QProcess::NormalExit && p.exitCode() == 0) {
        if (m_r.logger) m_r.logger(QStringLiteral("  started unit %1 (journalctl --user -u %1)").arg(unit));
        return true;
    }
    const QString why = QString::fromUtf8(p.readAllStandardError()).trimmed();
    if (m_r.logger) m_r.logger(QStringLiteral("  ! systemd-run failed (%1), starting pkexec directly").arg(why));
    if (QProcess::startDetached(QStringLiteral("pkexec"), helperArgs)) return true;
    if (err) *err = QStringLiteral("could not start the app: %1").arg(why.isEmpty() ? QStringLiteral("systemd-run and pkexec failed") : why);
    return false;
}

QHash<QString, int> Namespace::runningCounts() const
{
    QHash<QString, int> out;
    struct stat nsst {};
    const bool haveNs = ::stat((QByteArrayLiteral("/run/netns/") + cfg.ns.toLocal8Bit()).constData(), &nsst) == 0;
    const QByteArray slicePrefix = QByteArrayLiteral("0::/") + cfg.slice.toLocal8Bit() + '/';
    const uid_t me = ::getuid();
    const QStringList pids = QDir(QStringLiteral("/proc")).entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &pid : pids) {
        bool numeric = false;
        pid.toUInt(&numeric);
        if (!numeric) continue;
        const QByteArray base = QByteArrayLiteral("/proc/") + pid.toLatin1();
        struct stat pst {};
        if (::stat(base.constData(), &pst) != 0 || pst.st_uid != me) continue;
        bool inside = false;
        if (haveNs) {
            struct stat netst {};
            inside = ::stat((base + "/ns/net").constData(), &netst) == 0 && netst.st_ino == nsst.st_ino && netst.st_dev == nsst.st_dev;
        }
        if (!inside) {
            QFile cg(QString::fromLatin1(base + "/cgroup"));
            if (cg.open(QIODevice::ReadOnly)) {
                const QList<QByteArray> lines = cg.readAll().split('\n');
                for (const QByteArray &l : lines) if (l.startsWith(slicePrefix)) { inside = true; break; }
            }
        }
        if (!inside) continue;
        QFile env(QString::fromLatin1(base + "/environ"));
        if (!env.open(QIODevice::ReadOnly)) continue;
        QString app = QStringLiteral("?");
        const QList<QByteArray> vars = env.readAll().split('\0');
        for (const QByteArray &kv : vars)
            if (kv.startsWith("VPNKS_APP=")) { app = QString::fromLatin1(kv.mid(10)); break; }
        out[app]++;
    }
    return out;
}

QString Namespace::desktopEntryPath(const QString &id)
{
    return QStandardPaths::writableLocation(QStandardPaths::ApplicationsLocation) + QStringLiteral("/vpnks-") + id + QStringLiteral(".desktop");
}

bool Namespace::writeDesktopEntry(const AppEntry &a, QString *path, QString *err) const
{
    const QString p = desktopEntryPath(a.id);
    QDir().mkpath(QFileInfo(p).absolutePath());
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        if (err) *err = f.errorString();
        return false;
    }
    QString exe = QCoreApplication::applicationFilePath();
    exe.replace(QLatin1Char('\\'), QStringLiteral("\\\\")).replace(QLatin1Char('"'), QStringLiteral("\\\"")).replace(QLatin1Char('$'), QStringLiteral("\\$")).replace(QLatin1Char('`'), QStringLiteral("\\`"));
    const QString firstWord = a.command.section(QLatin1Char(' '), 0, 0, QString::SectionSkipEmpty);
    QTextStream o(&f);
    o << "[Desktop Entry]\n"
      << "Type=Application\n"
      << "Name=" << a.name << " (VPN)\n"
      << "Comment=Runs " << a.name << " inside the vpnks VPN namespace\n"
      << "Exec=\"" << exe << "\" --launch " << a.id << "\n"
      << "Icon=" << QFileInfo(firstWord).fileName() << "\n"
      << "Terminal=false\n"
      << "Categories=Network;\n";
    if (path) *path = p;
    return true;
}

void Namespace::removeDesktopEntry(const QString &id) { QFile::remove(desktopEntryPath(id)); }
