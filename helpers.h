
//
//  helpers.h
//  crashmon
//
//  Created by ant4g0nist on 01/11/2021.
//

#ifndef helpers_h
#define helpers_h

#include <sys/ioctl.h>

#define RET_NO_CRASH 0
#define RET_OTHER_SIG -2
#define RET_ERROR -1

#define HRED "\e[0;91m"
#define RED "\e[0;31m"
#define GRN "\e[0;32m"
#define RESET "\e[0m"

#define draw_line() do { \
    struct winsize w; \
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w); \
    printf(RED "%0*d" RESET, w.ws_col, 0); \
    printf("\n"); \
} while(0)

#define context_title(msg) do { \
    struct winsize w; \
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w); \
    printf(HRED "%0*d" RESET, 4, 0); \
    printf(GRN " [ "  RESET); \
    printf(msg); \
    printf(GRN " ] "  RESET); \
    printf(RED "%0*d" RESET, w.ws_col-(int)strlen(msg)-10, 0); \
    printf("\n"); \
} while(0)

#define debug(...)  { printf(GRN); printf(__VA_ARGS__); printf(RESET);}
#define debugn(...)  { printf(GRN); printf(__VA_ARGS__); printf(RESET); printf("\n");}
#define die(...) do { \
        debugn(RED "[-] PROGRAM ABORT : " RESET __VA_ARGS__); \
        debugn(RED "         Location" RESET " : %s(), %s:%u\n", \
            __FUNCTION__, __FILE__, __LINE__); \
        exit(1); \
    } while (0)

#endif /* helpers_h */
