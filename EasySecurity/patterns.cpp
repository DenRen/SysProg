#include "patterns.hpp"

namespace encryptor_patterns
{

using Event = es::Event;
using Repeats = es::EventHistoryPattern::EventScheme::Repeats;
using EventScheme = es::EventHistoryPattern::EventScheme;

es::EventHistoryPattern enc_pattern()
{
    return {
        EventScheme{Event::OPEN, 1},
        EventScheme{Event::ACCESS, 1, Repeats::MORE_EQUAL},
        EventScheme{Event::CLOSE_NOWRITE, 1},

        EventScheme{Event::OPEN, 1},
        EventScheme{Event::MODIFY, 1, Repeats::MORE_EQUAL},
        EventScheme{Event::CLOSE_WRITE, 1},
    };
}

}