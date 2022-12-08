#pragma once

#include <string>
#include <filesystem>

#include "types.hpp"
#include "sqlite3/sqlite3.h"

namespace es
{

class SqliteException
{
public:
    SqliteException(sqlite3* db, int err_code) noexcept
        : m_err_msg{ sqlite3_errmsg(db) }
        , m_err_code{ err_code }
    {
        sqlite3_close_v2(db);
    }

    const char* what() const noexcept
    {
        return m_err_msg;
    }

    int err_code() const noexcept
    {
        return m_err_code;
    }

private:
    const char* m_err_msg;
    int m_err_code;
};

class SQLite
{
public:
    SQLite(const FileName& db_path, int flags);
    ~SQLite();

    sqlite3* Get() noexcept
    {
        return m_db_conn;
    }

private:
    sqlite3* m_db_conn;
};

class FileStorage
{
public:
    FileStorage(const FileName& db_path);
    ~FileStorage();

    int64_t StoreFile(const FileName& path);
    int RestoreFile(int64_t id, const FileName& path);
    int ReleaseFile(int64_t id);

private:
    SQLite m_db;
};

class MilwareStorage
{

};


} // namespace es
