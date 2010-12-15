#include "exception.hh"
#include <cstdio>
#include <cstring>

errno_exception::errno_exception(int errno)
    : _errno(errno)
{
}

int errno_exception::errno() const
{
    return _errno;
}

const char *errno_exception::what()
{
    std::snprintf(_buf, sizeof _buf, "error: %s (%d)",
		  std::strerror(_errno), _errno);
    return _buf;
}
