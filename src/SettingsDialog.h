#pragma once
#include <QDialog>
#include "Config.h"

class QComboBox; class QLineEdit; class QCheckBox; class QPlainTextEdit;

class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    SettingsDialog(GlobalConfig cfg, QWidget *parent = nullptr);
    GlobalConfig config() const;
private slots:
    void importFromNetworkManager();
private:
    QComboBox *m_backend, *m_elev, *m_conn;
    QLineEdit *m_tunnel, *m_phys, *m_lan, *m_eps, *m_dns;
    QCheckBox *m_block6;
};
