#include "easy_security.hpp"

#include <sys/fanotify.h>

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

// EventHistory::EventHistory(std::size_t size)

} // namespace es
