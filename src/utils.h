#include <stddef.h>
#include <inttypes.h>

// Compares 2 strings
//
// Returns 1 if the strings are equal, 0 if they are different.
// Also returns 0 if one or both strings are NULL
int string_equal(const char *a, const char *b);

// Reads a positive integer from a string.
//
// Return values:
//   >= 0: The value of the integer
//   -1  : The string does not represent a positive integer
//   -2  : The number is too big to be represented as an int
int int_of_string(const char *s);

// Prints the contents of a buffer in hexadecimal form
void print_buffer(const uint8_t *buffer, size_t buffer_size);

// Reads a hexadecimal representation of a byte buffer.
//
// Return values:
//   >= 0: size of the buffer, in bytes
//   -1  : error, null string
//   -2  : error, buffer would exceed max_size
//   -3  : error, string has odd number of characters
//   -4  : error, string has non-hex digits
int read_buffer(uint8_t *out, size_t max_size, const char *hex);
