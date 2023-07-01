/*
 * Set up arguments for main() and prepare environment variables
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#ifndef _ARGV_H_
#define _ARGV_H_

extern void __setup_args(void);
extern void setup_args(const char *args);
extern void setup_args_progname(const char *args);
extern void setup_env(char *env, int size);
extern void add_setup_arg(const char *arg);

#endif
