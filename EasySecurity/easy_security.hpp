#pragma once

#include <cstdint>

#include <vector>
#include <string>
#include <map>

#include <boost/circular_buffer.hpp>

namespace es
{

enum class Event
{
    EMPTY = -1, // For unlistening or empty event
    OPEN,
    ACCESS,
    MODIFY,
    CLOSE_NOWRITE,
    CLOSE_WRITE
};

using FanotifyEvent = uint32_t;

// In event can be more the one setted bits.
// This function eject the bits in special prioritet.
// If event == 0 then it not containt any bites
Event FanotifyEvent2Event(FanotifyEvent& event) noexcept;

/// @brief { OPEN, MODIFY * (>= 1), CLOSE_WRITE }
class EventHistoryPattern
{
public:
    struct EventScheme
    {
        enum class Repeats // todo: change name
        {
            EQUAL,
            MORE,
            MORE_EQUAL
        };

        Event m_event;
        uint32_t m_number;
        Repeats m_repeats;
    };

    template <EventScheme... EventSchemes>
    EventHistoryPattern()
        : m_pattern{EventSchemes...}
    {}

    auto cbegin() const noexcept;
    auto cend() const noexcept;

private:
    std::vector<EventScheme> m_pattern;
};

class EventHistory
{
public:
    EventHistory(std::size_t size);
    void AddEvent(Event event);
    
    auto cbegin() const noexcept;
    auto cend() const noexcept;

private:
    boost::circular_buffer<Event> m_events;
};

template <typename EventHistoryIter, typename EventHistoryPatternIter>
bool FindPattern(EventHistoryIter event_begin, EventHistoryIter event_end,
                 EventHistoryPatternIter pattern_begin, EventHistoryPatternIter pattern_end);

class EasySecurity
{
public:
    void AddEvent(pid_t pid, FanotifyEvent event);

private:
    using FileName = std::string;
    using FilesHistory = std::map<FileName, EventHistory>;
    using ProcessesMap = std::map<pid_t, FilesHistory>;

    ProcessesMap m_proc_map;
};

} // namespace es
