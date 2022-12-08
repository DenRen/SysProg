#pragma once

#include <cstdint>

#include <vector>
#include <string>
#include <map>

#include "boost/circular_buffer.hpp"
#include "types.hpp"
#include "storage.hpp"

namespace es
{

enum class Event
{
    EMPTY = -1, // For unlistening or empty event
    OPEN,
    EXEC,
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

        constexpr EventScheme(Event event, uint32_t number, Repeats repeats = Repeats::EQUAL) noexcept
            : m_event{event}
            , m_number{number}
            , m_repeats{repeats}
        {}

        Event m_event;
        uint32_t m_number;
        Repeats m_repeats;
    };

    template <typename... EventSchemes>
    EventHistoryPattern(EventSchemes&&... eventSchemes)
        : m_pattern{std::forward<EventSchemes>(eventSchemes)...}
    {}

    auto cbegin() const noexcept;
    auto cend() const noexcept;

private:
    std::vector<EventScheme> m_pattern;
};

class EventHistory
{
public:
    explicit EventHistory(std::size_t size = 1024);
    void AddEvent(Event event);

    auto begin() const noexcept;
    auto end() const noexcept;

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
    using Pattern = EventHistoryPattern;
    using Patterns = std::vector<EventHistoryPattern>;
    EasySecurity(Patterns encrypter_patterns, const FileName& file_db_name);

    bool Step(pid_t pid, int event_fd, FanotifyEvent fan_event, int fan_fd, uint64_t mask);

private:
    bool AddFanotifyEvent(FanotifyEvent& fan_event, EventHistory& event_history);
    bool CheckOnMalwarePatterns(const EventHistory& event_history);

    int64_t TryBackupFile(const FileName& path);
    void TryRestoreFile(int64_t id, const FileName& path);
    void TryReleaseFile(int64_t id);

    void LogPatternMatching(pid_t detected_process_pid, const FileName& path);
    void StopProcess(pid_t pid);
    void KillProcess(pid_t pid);

private:
    class FileInfo
    {
    public:
        EventHistory& GetEventHistory() noexcept { return m_event_history; }
        const EventHistory& GetEventHistory() const noexcept { return m_event_history; }

        int64_t GetBackupId() const noexcept { return m_backup_id; }
        void SetBackupId(int64_t backup_id) noexcept { m_backup_id = backup_id; }

    private:
        EventHistory m_event_history;
        int64_t m_backup_id = -1;
    };

    using FilesInfo = std::map<FileName, FileInfo>;
    using ProcessesMap = std::map<pid_t, FilesInfo>;

    ProcessesMap m_proc_map;
    Patterns m_encrypter_patterns;
    FileStorage m_file_storage;
};

template <typename EventHistoryIter, typename EventHistoryPatternIter>
bool FindPattern(EventHistoryIter event_begin, EventHistoryIter event_end,
                 EventHistoryPatternIter pattern_begin, EventHistoryPatternIter pattern_end)
{
    using Event = es::Event;
    using Repeats = es::EventHistoryPattern::EventScheme::Repeats;
    using EventScheme = es::EventHistoryPattern::EventScheme;

    auto it_event = event_begin;
    for (auto it_patt = pattern_begin; it_patt != pattern_end; ++it_patt)
    {
        if (it_event == event_end)
            return false;

        switch (it_patt->m_repeats)
        {
        case Repeats::EQUAL:
            for (uint32_t ctr = 0; ctr < it_patt->m_number && it_event != event_end; ++ctr, ++it_event)
                if (*it_event != it_patt->m_event)
                    return false;
            break;
        case Repeats::MORE:
            for (uint32_t ctr = 0; ctr < (it_patt->m_number + 1) && it_event != event_end; ++ctr, ++it_event)
                if (*it_event != it_patt->m_event)
                    return false;

            while(it_event != event_end && *it_event == it_patt->m_event)
                ++it_event;

            break;
        case Repeats::MORE_EQUAL:
            for (uint32_t ctr = 0; ctr < it_patt->m_number && it_event != event_end; ++ctr, ++it_event)
                if (*it_event != it_patt->m_event)
                    return false;

            while(it_event != event_end && *it_event == it_patt->m_event)
                ++it_event;

            break;
        default:
            throw std::runtime_error("incorrect repeats");
        }
    }

    return true;
}

class IgnoreGuard
{
public:
    IgnoreGuard(int fanotify_fd, uint64_t mask, const char* file_path);
    ~IgnoreGuard();

private:
    const char* m_path;
    uint64_t m_mask;
    int m_fd;
};

} // namespace es
