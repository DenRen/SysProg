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

EasySecurity::EasySecurity(Patterns patterns, bool enable_stop_detected_process)
    : m_patterns(std::move(patterns))
    , m_stop_detected_process(enable_stop_detected_process)
{}

void EasySecurity::Step(pid_t pid, int event_fd, FanotifyEvent fan_event)
{
    FileName file_name = proc::GetFileName(event_fd);

    FilesHistory& file_history = m_proc_map[pid];
    auto[event_history_it, eh_emplaced] = file_history.try_emplace(std::move(file_name));
    EventHistory& event_history = event_history_it->second;

    AddFanotifyEvent(fan_event, event_history);
    if (CheckEventHistoryOnPatterns(event_history))
    {
        auto comm = proc::GetProcComm(pid);
        printf("Find encrypt pattern!\n"
               "    pid: %d" 
               "    comm: %s\n"
               "    file: %s\n", pid, comm.c_str(), event_history_it->first.c_str());

        if (m_stop_detected_process)
        {
            if (kill(pid, SIGSTOP) < 0)
                perror("Action: Failed to send stop signal");
            else
                printf("Action: stoped\n");
        }
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
