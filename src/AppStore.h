#pragma once
#include <QString>
#include <QVector>

struct AppEntry { QString id, name, command; };

class AppStore {
public:
    AppStore();
    QVector<AppEntry> apps;
    bool load();
    bool save() const;
    static QString sanitizeId(const QString &name);   // [a-z0-9_], used in unit names and env
private:
    QString m_path;
};
