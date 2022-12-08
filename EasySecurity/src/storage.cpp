#include <fstream>

#include "storage.hpp"
#include "boost/interprocess/mapped_region.hpp"
#include "boost/interprocess/file_mapping.hpp"
#include "fmt/format.h"

namespace es
{

constexpr static const char* StoreTableName = "BackupFiles";

SQLite::SQLite(const FileName& db_path, int flags)
{
    if (int err = sqlite3_open_v2(db_path.c_str(), &m_db_conn, flags, NULL); err != SQLITE_OK)
        throw SqliteException{m_db_conn, err};
}

SQLite::~SQLite()
{
    sqlite3_close_v2(m_db_conn);
}

constexpr static inline int
    s_db_open_flags = 0
                      | SQLITE_OPEN_READWRITE
                      | SQLITE_OPEN_CREATE
                      | SQLITE_OPEN_PRIVATECACHE
                      | SQLITE_OPEN_EXRESCODE     // Extended result code
                      | SQLITE_OPEN_NOFOLLOW      // The database filename is not allowed to contain a symbolic link
                      ;

FileStorage::FileStorage(const FileName& db_path)
    : m_db{db_path.c_str(), s_db_open_flags}
{
    /*
        I don't use pair of path and pid as primary key, because it can create the stalemate.
        Imagine, process created two threads, each of them opened and started to write in to the
        same file. In terms of path-pid pair it is has no difference.
    */
    auto create_table_cmd = fmt::format(
        "CREATE TABLE IF NOT EXISTS {} ("
            "id INTEGER PRIMARY KEY,"
            "file blob NOT NULL"
        ")", StoreTableName
    );

    sqlite3* db = m_db.Get();
    sqlite3_stmt* stmt = nullptr;
    int err = sqlite3_prepare_v2(db, create_table_cmd.c_str(), create_table_cmd.size(), &stmt, nullptr);
    if (err != SQLITE_OK)
        throw SqliteException(db, err);

    err = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (err != SQLITE_DONE)
        throw SqliteException(db, err);
}

FileStorage::~FileStorage()
{}

int64_t FileStorage::StoreFile(const FileName& path)
{
    // Init mapping for file
    const boost::interprocess::mode_t fm_mode = boost::interprocess::read_only;
    boost::interprocess::file_mapping file_mapping{path.c_str(), fm_mode};
    boost::interprocess::mapped_region region{file_mapping, fm_mode, 0, 0};

    const auto* file_buf = static_cast<const uint8_t*>(region.get_address());
    const auto file_size = region.get_size();
    if (file_size > 1024 * 1024 * 1024)
        return -1;

    // Prepate SQL statement
    auto insert_cmd = fmt::format("INSERT INTO {}(file) VALUES(?)", StoreTableName);

    sqlite3* db = m_db.Get();
    sqlite3_stmt* stmt = nullptr;
    if (int err = sqlite3_prepare_v2(db, insert_cmd.c_str(), insert_cmd.size(), &stmt, nullptr); err != SQLITE_OK)
        throw SqliteException(db, err);

    if (int err = sqlite3_bind_blob64(stmt, 1, file_buf, file_size, SQLITE_STATIC); err != SQLITE_OK)
    {
        sqlite3_finalize(stmt);
        throw SqliteException(db, err);
    }

    int err = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (err != SQLITE_DONE)
    {
        if (err == SQLITE_NOTFOUND)
            return -1;

        throw SqliteException(db, err);
    }

    int64_t id = sqlite3_last_insert_rowid(db);
    return id;
}

int FileStorage::RestoreFile(int64_t id, const FileName& path)
{
    // Prepate SQL statement
    auto select_cmd = fmt::format("SELECT file FROM {} WHERE id = {}", StoreTableName, id);

    sqlite3* db = m_db.Get();
    sqlite3_stmt* stmt = nullptr;
    if (int err = sqlite3_prepare_v2(db, select_cmd.c_str(), select_cmd.size(), &stmt, nullptr); err != SQLITE_OK)
        throw SqliteException(db, err);

    if (int err = sqlite3_step(stmt); err != SQLITE_ROW)
    {
        sqlite3_finalize(stmt);
        if (err == SQLITE_NOTFOUND)
            return -1;

        throw SqliteException(db, err);
    }

    int file_size = sqlite3_column_bytes(stmt, 0);

    std::ofstream file{path, std::ios::binary | std::ios::out };
    file.write((const char*)sqlite3_column_blob(stmt, 0), file_size);

    sqlite3_finalize(stmt);

    return 0;
}

int FileStorage::ReleaseFile(int64_t id)
{
    // Prepate SQL statement
    auto delete_cmd = fmt::format("DELETE FROM {} WHERE id = {}", StoreTableName, id);

    sqlite3* db = m_db.Get();
    sqlite3_stmt* stmt = nullptr;
    if (int err = sqlite3_prepare_v2(db, delete_cmd.c_str(), delete_cmd.size(), &stmt, nullptr); err != SQLITE_OK)
        throw SqliteException(db, err);

    int err = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (err != SQLITE_DONE)
    {
        if (err == SQLITE_NOTFOUND)
            return -1;

        throw SqliteException(db, err);
    }

    return 0;
}

} // namespace es
