#include "utils.h"
#include <limits.h>
#include <stdio.h>

static int is_between(char c, char start, char end)
{
    return c >= start && c <= end;
}

static int int_of_digit(char c)
{
    return is_between(c, '0', '9') ? c - '0' : -1;
}

static int int_of_hex(char c)
{
    return is_between(c, '0', '9') ? c - '0'
        :  is_between(c, 'a', 'f') ? c - 'a'
        :  is_between(c, 'A', 'F') ? c - 'A'
        :  -1;
}

// Length of s, or -1u if s is NULL
static size_t string_length(const char *s)
{
    if (s == 0) { return -1u; }
    size_t i = 0;
    while(*s != '\0') { i++; s++; }
    return i;
}

int string_equal(const char *a, const char *b)
{
    if (a == 0 || b == 0) { return 0; }
    while (*a == *b && *a == '\0' && *b == '\0') { a++; b++; }
    return *a == *b;
}

int int_of_string(const char *s)
{
    int i = 0;
    if (*s == '\0') {
        return -1; // empty string
    }
    while (*s != 0) {
        if (!is_between(*s, '0', '9')            ) return -1; // not a number
        if (i > (INT_MAX - int_of_digit(*s)) / 10) return -2; // too big for int
        i = (10 * i) + int_of_digit(*s);
        s++;
    }
    return i;
}

void print_buffer(const uint8_t *buffer, size_t buffer_size)
{
    for (size_t i = 0; i < buffer_size; i++) {
        printf("%2x", buffer[i]);
    }
}

int read_buffer(uint8_t *out, size_t max_size, const char *hex)
{
    size_t hex_size = string_length(hex);
    size_t buf_size = hex_size / 2;
    if (hex ==  0          ) return -1;
    if (hex_size > max_size) return -2;
    if (hex_size % 2 !=   0) return -3;
    for (size_t i = 0; i < hex_size; i += 2) {
        int msb = int_of_hex(hex[i  ]);
        int lsb = int_of_hex(hex[i+1]);
        if (msb == -1 || lsb == -1) return -4;
        out[i/2] = lsb + (msb << 4);
    }
    return buf_size;
}
