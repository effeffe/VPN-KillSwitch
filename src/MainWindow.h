#pragma once
#include <QHash>
#include <QMainWindow>
#include <QSystemTrayIcon>
#include "AppStore.h"
#include "Killswitch.h"
#include "Namespace.h"

class QTableWidget; class QLabel; class QMenu; class QTimer; class QPushButton; class QPlainTextEdit; class QComboBox;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow(Killswitch &ks, Namespace &ns, bool startHidden, QWidget *parent = nullptr);
protected:
    void closeEvent(QCloseEvent *e) override;
private slots:
    void toggleArmed(bool on);
    void openSettings();
    void createSplitProfile();
    void changeMethod(int index);
    void nsSetup();
    void nsTeardown();
    void addApp();
    void removeApp();
    void launchSelected();
    void addToAppMenu();
    void refresh();
    void refreshLive();
    void onTrayActivated(QSystemTrayIcon::ActivationReason r);
private:
    void rebuildTable();
    void updateRows();
    void updateNsStatus();
    void refreshRules();
    void rebuildTrayMenu();
    void showArmed(bool armed);
    void launchApp(const AppEntry &a);
    void setupTray();
    void bringToFront();

    Killswitch &m_ks;
    Namespace &m_ns;
    AppStore m_store;
    NsState m_nsState;
    QHash<QString, int> m_counts;
    QString m_rulesTag, m_rulesWarn;
    bool m_armed = false;
    QString m_lastDev;
    QStringList m_lastUplinks;

    QPushButton *m_armBtn = nullptr;
    QLabel *m_armLabel = nullptr;
    QLabel *m_status = nullptr;
    QLabel *m_nsLabel = nullptr;
    QComboBox *m_methodCombo = nullptr;
    QPushButton *m_setupBtn = nullptr;
    QPushButton *m_teardownBtn = nullptr;
    QTableWidget *m_table = nullptr;
    QPlainTextEdit *m_log = nullptr;
    QSystemTrayIcon *m_tray = nullptr;
    QMenu *m_trayMenu = nullptr;
    QTimer *m_liveTimer = nullptr;
    QTimer *m_trayProbe = nullptr;
    int m_trayProbes = 0;
    bool m_startHidden = false;
};
