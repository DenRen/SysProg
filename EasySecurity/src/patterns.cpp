#include "patterns.hpp"

namespace encryptor_patterns
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

}