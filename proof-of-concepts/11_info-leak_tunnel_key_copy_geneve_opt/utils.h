#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>

#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN "\033[36m"
#define COLOR_WHITE "\033[37m"

#define LOG_ERROR(fmt, ...) \
    fprintf(stderr, COLOR_RED "[ERROR] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define LOG_WARNING(fmt, ...) \
    fprintf(stderr, COLOR_YELLOW "[WARNING] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define LOG_INFO(fmt, ...) \
    fprintf(stdout, COLOR_GREEN "[INFO] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#ifdef DEBUG
#define LOG_DEBUG(fmt, ...) \
    fprintf(stdout, COLOR_CYAN "[DEBUG] " fmt COLOR_RESET "\n", ##__VA_ARGS__)
#else
#define LOG_DEBUG(fmt, ...) \
    do                      \
    {                       \
    } while (0)
#endif

#define LOG_TRACE(fmt, ...) \
    fprintf(stdout, COLOR_MAGENTA "[TRACE] " fmt COLOR_RESET "\n", ##__VA_ARGS__)

#define errExit(msg)        \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0)

void buffer2hex(const unsigned char *buffer, size_t size)
{
    for (size_t i = 0; i < size; i++)
    {
        if (i % 16 == 0)
        {
            printf("%02lx:\t", i);
        }
        printf("%02X ", buffer[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
}

#endif