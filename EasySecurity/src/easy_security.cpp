#include "easy_security.hpp"
#include "proc_processor.hpp"

#include <sys/fanotify.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>

namespace es
{

/// @brief
/// To separate the events in correct order, used the rools from fanotify docs:
/// "
///     Multiple bits may be set in this mask, if more than one event occurred
///     for the monitored filesystem object.  In particular, consecutive events
///     for the same filesystem object and originating from the same process
///     may be merged into a single event, with the exception that two
///     permission events are never merged into one queue entry.
/// "
/// Therefore, for example, it is possible to correctly separate OPEN and
/// ACCESS by ignoring FAN_OPEN and FAN_ACCESS, and responding to the
/// FAN_OPEN_PERM and FAN_ACCESS_PERM, because the latter cannot come together.
///
/// @param event from read of fanotify file descriptor
/// @return current Event
Event FanotifyEvent2Event(FanotifyEvent& event) noexcept
{
    FanotifyEvent flag {};
    return (flag = event & FAN_OPEN_PERM)       ? (event ^= flag, Event::OPEN)          :
           (flag = event & FAN_OPEN_EXEC_PERM)  ? (event ^= flag, Event::EXEC)          :
           (flag = event & FAN_ACCESS_PERM)     ? (event ^= flag, Event::ACCESS)        :
           (flag = event & FAN_MODIFY)          ? (event ^= flag, Event::MODIFY)        :
           (flag = event & FAN_CLOSE_WRITE)     ? (event ^= flag, Event::CLOSE_WRITE)   :
           (flag = event & FAN_CLOSE_NOWRITE)   ? (event ^= flag, Event::CLOSE_NOWRITE) :
           Event::EMPTY;
}

auto EventHistoryPattern::cbegin() const noexcept
{
    return m_pattern.rbegin();
}

auto EventHistoryPattern::cend() const noexcept
{
    return m_pattern.rend();
}

EventHistory::EventHistory(std::size_t size)
    : m_events(size)
{}

void EventHistory::AddEvent(Event event)
{
    m_events.push_back(event);
}

auto EventHistory::cbegin() const noexcept
{
    return m_events.rbegin();
}

auto EventHistory::cend() const noexcept
{
    return m_events.rend();
}

auto EventHistory::begin() const noexcept
{
    return cbegin();
}

auto EventHistory::end() const noexcept
{
    return cend();
}

EasySecurity::EasySecurity(Patterns encrypter_patterns, const FileName& file_db_name)
    : m_encrypter_patterns(std::move(encrypter_patterns))
    , m_file_storage{file_db_name}
{}

static void PrintEvent(Event event)
{
    switch(event)
    {
        case Event::EMPTY:
            printf("EMPTY\n");
            break;
        case Event::OPEN:
            printf("OPEN\n");
            break;
        case Event::EXEC:
            printf("EXEC\n");
            break;
        case Event::ACCESS:
            printf("ACCESS\n");
            break;
        case Event::MODIFY:
            printf("MODIFY\n");
            break;
        case Event::CLOSE_NOWRITE:
            printf("CLOSE_NOWRITE\n");
            break;
        case Event::CLOSE_WRITE:
            printf("CLOSE_WRITE\n");
            break;
        default:
            printf("Unknown Event\n");
    }
}

static void PrintEventHistory(const EventHistory& event_history)
{
    for (const auto& event : event_history)
        PrintEvent(event);
}

bool EasySecurity::Step(pid_t pid, int event_fd, FanotifyEvent fan_event, int fan_fd, uint64_t mask)
{
    FilesInfo& files_info = m_proc_map[pid];
    auto[file_info_it, eh_emplaced] = files_info.try_emplace(proc::GetFileName(event_fd));
    FileInfo& file_info = file_info_it->second;
    EventHistory& event_history = file_info.GetEventHistory();
    const FileName& file_path = file_info_it->first;

    bool is_need_close = true;
    while(AddFanotifyEvent(fan_event, event_history))
    {
        const auto last_event = *event_history.cbegin();
        if (last_event == Event::OPEN)                          // TODO: Understand why FAN_CLASS_PRE_CONTENT not work
        {
            IgnoreGuard file_ignore_guard{fan_fd, mask, file_path.c_str()};
            auto id = TryBackupFile(file_path);
            if (id >= 0)
                file_info.SetBackupId(id);
        }

        // Find malware behavior
        if (CheckOnMalwarePatterns(event_history))
        {
            LogPatternMatching(pid, file_path);
            KillProcess(pid);
            close(event_fd);

            is_need_close = false;
            if (auto file_id = file_info.GetBackupId(); file_id >= 0)
            {
                IgnoreGuard file_ignore_guard{fan_fd, mask, file_path.c_str()};
                TryRestoreFile(file_id, file_path);
            }

            m_proc_map.erase(pid);

            break;
        }

        // Here we can safety remove file from storage
        if (last_event == Event::CLOSE_NOWRITE || last_event == Event::CLOSE_WRITE)
        {
            TryReleaseFile(file_info.GetBackupId());

            break;
        }
    }

    return is_need_close;
}

bool EasySecurity::AddFanotifyEvent(FanotifyEvent& fan_event, EventHistory& event_history)
{
    Event event = FanotifyEvent2Event(fan_event);
    if (event != Event::EMPTY)
    {
        event_history.AddEvent(event);
        return true;
    }

    return false;
}

bool EasySecurity::CheckOnMalwarePatterns(const EventHistory& event_history)
{
    const auto event_begin = event_history.cbegin();
    const auto event_end = event_history.cend();

    for (const EventHistoryPattern& pattern : m_encrypter_patterns)
        if (FindPattern(event_begin, event_end, pattern.cbegin(), pattern.cend()))
            return true;

    return false;
}

int64_t EasySecurity::TryBackupFile(const FileName& path)
{
    // TODO: Add logging to empty catchs
    try
    {
        int64_t id = m_file_storage.StoreFile(path);
        return id;  // If -1 - then too big
    }
    catch(SqliteException& sql_exc)
    {
        return -1;  // SQLite error
    }
    catch(std::exception& exc)
    {
        return -1;  // Is not exist (boost exception)
    }
}

void EasySecurity::TryRestoreFile(int64_t id, const FileName& path)
{
    // TODO: Add logging to empty catch
    try
    {
        // Ignore not founded file
        if (m_file_storage.RestoreFile(id, path) >= 0)
            (void)m_file_storage.ReleaseFile(id);
    }
    catch(SqliteException& sql_exc)
    {
        // SQLite error
    }
}

void EasySecurity::TryReleaseFile(int64_t id)
{
    // TODO: Add logging to empty catch
    try
    {
        if (id >= 0)
            (void)m_file_storage.ReleaseFile(id);
    }
    catch(SqliteException& sql_exc)
    {
        // SQLite error
    }
}

void EasySecurity::LogPatternMatching(pid_t detected_process_pid, const FileName& path)
{
    auto comm = proc::GetProcComm(detected_process_pid);
    printf("Find encrypt pattern!\n"
            "    pid: %d"
            "    comm: %s\n"
            "    file: %s\n", detected_process_pid, comm.c_str(), path.c_str());
}

void EasySecurity::StopProcess(pid_t pid)
{
    if (kill(pid, SIGSTOP) < 0)
        perror("Action: Failed to send stop signal");
    else
        printf("Action: stoped\n");
}

void EasySecurity::KillProcess(pid_t pid)
{
    if (kill(pid, SIGKILL) < 0)
        perror("Action: Failed to send kill signal");
    else
        printf("Action: killed\n");
}

IgnoreGuard::IgnoreGuard(int fanotify_fd, uint64_t mask, const char* file_path)
    : m_path{ file_path }
    , m_mask{ mask }
    , m_fd{ fanotify_fd }
{
    fanotify_mark(m_fd, FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY, m_mask, 0, m_path);
}

IgnoreGuard::~IgnoreGuard()
{
    fanotify_mark(m_fd, FAN_MARK_REMOVE | FAN_MARK_IGNORED_MASK, m_mask, 0, m_path);
}

} // namespace es
