#include <QApplication>
#include <QIcon>
#include <QCoreApplication>
#include <QTextStream>
#include "AppStore.h"
#include "Killswitch.h"
#include "MainWindow.h"
#include "Namespace.h"

static int cli(const QStringList &args, Killswitch &ks, Namespace &ns)
{
    QTextStream out(stdout);
    ks.runner.logger = [&](const QString &s) { out << s << '\n'; out.flush(); };
    QString err;
    ks.updatePeers();   // the live VPN peers go into the killswitch and cgroup rules
    if (args.contains(QStringLiteral("--launch"))) {
        const QString id = args.value(args.indexOf(QStringLiteral("--launch")) + 1);
        AppStore store;
        store.load();
        for (const AppEntry &a : std::as_const(store.apps))
            if (a.id == id) {
                QString warn;
                if (!ns.ensureAppRules(ks, &err, &warn)) { out << "FAILED: not launching without firewall rules: " << err << '\n'; return 1; }
                if (!warn.isEmpty()) out << "warning: " << warn << '\n';
                if (ns.launch(a, &err)) return 0;
                out << "FAILED: " << err << '\n';
                return 1;
            }
        out << "unknown app id '" << id << "' (add it in the vpnks window first)\n";
        return 2;
    }
    if (args.contains(QStringLiteral("--status"))) {
        const NsState s = ns.state();
        out << "backend: " << ks.backendName() << "\narmed: " << (ks.isArmed() ? "yes" : "no") << '\n'
            << "per-app method: " << Namespace::modeLabel(ns.mode()) << '\n'
            << "namespace: " << (s.nsPresent ? "present" : "absent")
            << (s.tunnelAttached ? QStringLiteral(", tunnel attached (vip %1, dns %2)").arg(s.vip, s.dns) : QStringLiteral(", no tunnel")) << '\n';
        if (ns.isCgroup()) {
            const QString have = ks.appRulesTag(), want = ns.ruleSpec(ks).tag;
            out << "cgroup rules: " << (have.isEmpty() ? QStringLiteral("not loaded") : have == want ? have : have + QStringLiteral(" (outdated, want ") + want + ')')
                << "\nprocesses in " << ns.cfg.slice << ": " << ns.sliceProcessCount() << '\n';
        }
        return 0;
    }
    if (args.contains(QStringLiteral("--arm")))    { const bool ok = ks.arm(&err);    out << (ok ? "armed" : "FAILED: " + err) << '\n'; return ok ? 0 : 1; }
    if (args.contains(QStringLiteral("--disarm"))) { const bool ok = ks.disarm(&err); out << (ok ? "disarmed" : "FAILED: " + err) << '\n'; return ok ? 0 : 1; }
    return 0;
}

int main(int argc, char **argv)
{
    QCoreApplication::setApplicationName(QStringLiteral("vpnks"));
    QCoreApplication::setOrganizationName(QStringLiteral("vpnks"));
    const QStringList args = [&] { QStringList a; for (int i = 1; i < argc; ++i) a << QString::fromLocal8Bit(argv[i]); return a; }();
    const bool headless = args.contains(QStringLiteral("--arm")) || args.contains(QStringLiteral("--disarm"))
                       || args.contains(QStringLiteral("--status")) || args.contains(QStringLiteral("--launch"));

    if (headless) {
        QCoreApplication app(argc, argv);
        Killswitch ks;
        ks.runner.dryRun = args.contains(QStringLiteral("--dry-run"));
        Namespace ns(ks.runner);
        return cli(args, ks, ns);
    }

    QApplication app(argc, argv);
    QApplication::setQuitOnLastWindowClosed(false);
    QApplication::setApplicationDisplayName(QStringLiteral("VPN killswitch"));
    // Wayland has no per-window icon protocol: the compositor maps app_id -> .desktop -> Icon=.
    // X11 uses the explicit window icon. Set both.
    QGuiApplication::setDesktopFileName(QStringLiteral("vpnks"));
    QApplication::setWindowIcon(QIcon::fromTheme(QStringLiteral("vpnks"), QIcon::fromTheme(QStringLiteral("network-vpn"))));
    Killswitch ks;
    ks.runner.dryRun = args.contains(QStringLiteral("--dry-run"));
    Namespace ns(ks.runner);
    const bool hidden = args.contains(QStringLiteral("--hidden"));
    MainWindow w(ks, ns, hidden);
    if (!hidden) w.show();
    return app.exec();
}
