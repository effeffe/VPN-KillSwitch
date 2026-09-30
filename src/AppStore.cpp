#include "AppStore.h"
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStandardPaths>

AppStore::AppStore()
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(dir);
    m_path = dir + QStringLiteral("/apps.json");
}

bool AppStore::load()
{
    QFile f(m_path);
    if (!f.open(QIODevice::ReadOnly)) return false;
    apps.clear();
    for (const QJsonValue &v : QJsonDocument::fromJson(f.readAll()).array()) {
        const QJsonObject o = v.toObject();
        apps.push_back({o.value(QStringLiteral("id")).toString(), o.value(QStringLiteral("name")).toString(), o.value(QStringLiteral("command")).toString()});
    }
    return true;
}

bool AppStore::save() const
{
    QJsonArray arr;
    for (const AppEntry &a : apps)
        arr.append(QJsonObject{{QStringLiteral("id"), a.id}, {QStringLiteral("name"), a.name}, {QStringLiteral("command"), a.command}});
    QFile f(m_path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) return false;
    f.write(QJsonDocument(arr).toJson(QJsonDocument::Indented));
    return true;
}

QString AppStore::sanitizeId(const QString &name)
{
    QString id = name.toLower();
    id.replace(QRegularExpression(QStringLiteral("[^a-z0-9]+")), QStringLiteral("_"));
    id.remove(QRegularExpression(QStringLiteral("^_+|_+$")));
    return id.isEmpty() ? QStringLiteral("app") : id.left(48);
}
