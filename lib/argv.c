#include "libcflat.h"
#include "auxinfo.h"

int __argc;
char *__argv[100];
char *__args;

static char args_copy[1000];
static char *copy_ptr = args_copy;

static bool isblank(char p)
{
    return p == ' ' || p == '\t';
}

static char *skip_blanks(char *p)
{
    while (isblank(*p))
        ++p;
    return p;
}

void __setup_args(void)
{
    char *args = __args;
    char **argv = __argv + __argc;

    while (*(args = skip_blanks(args)) != '\0') {
        *argv++ = copy_ptr;
        while (*args != '\0' && !isblank(*args))
            *copy_ptr++ = *args++;
        *copy_ptr++ = '\0';
    }
    __argc = argv - __argv;
}

void setup_args(char *args)
{
    if (!args)
        return;

    __args = args;
    __setup_args();
}

void setup_args_prognam(char *args)
{
    __argv[0] = copy_ptr;
    strcpy(__argv[0], auxinfo.prognam);
    copy_ptr += strlen(auxinfo.prognam) + 1;
    ++__argc;
    if (args) {
        __args = args;
        __setup_args();
    }
}
