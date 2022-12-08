#include <filesystem>
#include <fstream>
#include <iostream>

#include "proc_processor.hpp"
#include "fmt/format.h"

namespace proc
{

std::string GetFileName(int fd)
{
    return std::filesystem::read_symlink(fmt::format("/proc/self/fd/{}", fd));
}

std::string GetProcComm(int fd)
{
    std::string path = fmt::format("/proc/{}/comm", fd);
    std::ifstream comm{ path.c_str() };
    comm >> path;
    return path;
}

} // namespace proc
