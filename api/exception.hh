#ifndef EXCEPTION_HH
#define EXCEPTION_HH

#include <exception>

class errno_exception : public std::exception {
public:
    explicit errno_exception(int err_no);
    int errno() const;
    virtual const char *what();
private:
    int _errno;
    char _buf[1000];
};

#endif
