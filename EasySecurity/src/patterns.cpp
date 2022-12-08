#include "patterns.hpp"

namespace patterns
{

using Event = es::Event;
using Repeats = es::EventHistoryPattern::EventScheme::Repeats;
using EventScheme = es::EventHistoryPattern::EventScheme;

es::EventHistoryPattern encrypt_file_use_fseek()
{
    return {
        EventScheme{Event::OPEN, 1},
        EventScheme{Event::ACCESS, 2 + 1, Repeats::MORE_EQUAL}, // fseek x2, read x1, x2, x3, ...
        EventScheme{Event::CLOSE_NOWRITE, 1},

        EventScheme{Event::OPEN, 1},
        EventScheme{Event::MODIFY, 1, Repeats::MORE_EQUAL}, // write x1, x2, x3, ...
        EventScheme{Event::CLOSE_WRITE, 1},
    };
}

es::EventHistoryPattern open_on_write()
{
    return {
        EventScheme{Event::OPEN, 1},
        // EventScheme{Event::MODIFY, 1}    // TODO: Understand why FAN_CLASS_PRE_CONTENT not work
    };
}

}