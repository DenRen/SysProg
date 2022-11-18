#include "easy_security.hpp"

#include <sys/fanotify.h>
#include <fcntl.h>
#include <limits.h>

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
    return (flag = event & FAN_OPEN_PERM)     ? (event ^= flag, Event::OPEN)          :
           (flag = event & FAN_ACCESS_PERM)   ? (event ^= flag, Event::ACCESS)        :
           (flag = event & FAN_MODIFY)        ? (event ^= flag, Event::MODIFY)        :
           (flag = event & FAN_CLOSE_WRITE)   ? (event ^= flag, Event::CLOSE_WRITE)   :
           (flag = event & FAN_CLOSE_NOWRITE) ? (event ^= flag, Event::CLOSE_NOWRITE) :
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

static std::string GetFileName(int fd)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);

    int nbytes = readlink(path, path, sizeof(path));
    if (nbytes <= 0)
        return {};

    path[nbytes] = '\0';

    return path;
}

static std::string GetProcComm(int fd)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/comm", fd);

    int proc_fd = open(path, O_RDONLY);
    if (proc_fd < 0)
    {
        perror("open");
        return {"inv 0"};
    }
    
    int nbytes = read(proc_fd, path, sizeof(path));
    if (nbytes <= 0)
        return {"inv 1"};

    path[nbytes - 1] = '\0';

    close(proc_fd);

    return path;
}

EasySecurity::EasySecurity(Patterns patterns)
    : m_patterns(std::move(patterns))
{}

void EasySecurity::Step(pid_t pid, int event_fd, FanotifyEvent fan_event)
{
    FileName file_name = GetFileName(event_fd);

    FilesHistory& file_history = m_proc_map[pid];
    EventHistory& event_history = file_history[file_name];

    AddFanotifyEvent(fan_event, event_history);
    if (CheckEventHistoryOnPatterns(event_history))
    {
        auto comm = GetProcComm(event_fd);
        printf("Find encrypt pattern!\n"
               "    pid: %d" 
               "    comm: %s\n"
               "    file: %s\n", pid, comm.c_str(), file_name.c_str());
    }
}

void EasySecurity::AddFanotifyEvent(FanotifyEvent fan_event, EventHistory& event_history)
{
    Event event = Event::EMPTY;
    while ((event = FanotifyEvent2Event(fan_event)) != Event::EMPTY)
        event_history.AddEvent(event);
}

bool EasySecurity::CheckEventHistoryOnPatterns(const EventHistory& event_history)
{
    const auto event_begin = event_history.cbegin();
    const auto event_end = event_history.cend();

    for (const EventHistoryPattern& pattern : m_patterns)
        if (FindPattern(event_begin, event_end, pattern.cbegin(), pattern.cend()))
            return true;

    return false;    
}

} // namespace es
