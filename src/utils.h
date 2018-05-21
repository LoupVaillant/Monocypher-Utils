#include <stddef.h>
#include <inttypes.h>

// Allocate a buffer.  Panics if allocation fails
void* alloc(size_t size);

// Fill buffer with random bytes.
// Panics if buffer_size > 256, or if the system call fails (it shouldn't).
void random_bytes(uint8_t *buffer, size_t buffer_size);

// Compares 2 strings
//
// Returns 1 if the strings are equal, 0 if they are different.
// Also returns 0 if one or both strings are NULL
int string_equal(const char *a, const char *b);

// Reads a positive integer from a string.
//
// Return values:
//   >= 0: The value of the integer
//   -1  : The string is NULL
//   -2  : The string does not represent a positive integer
//   -3  : The number is too big to be represented as an int
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

typedef struct {
    uint8_t *buffer;
    size_t   size;
} vector;

vector new_vector();

// Reads a hexadecimal representation of a byte buffer (allocates a vector)
// Returns the same as read_buffer
int read_vector(vector *v, const char *hex);

void free_vector(vector *v);

void set_usage_string(const char* usage); // sets usage string for user errors
void usage();                  // Prints usage string and exits
void error(const char *error); // Prints user    error, exits with code 1
void panic(const char *error); // Prints runtime error, exits with code 2

// Option parsing macros
// Use thus:
//     getopt_ctx ctx;
//     OPT_BEGIN(ctx, argc, argv);
//     OPT('f', "foo" );  process_foo();
//     OPT('b', "bar" );  process_bar();
//     OPT('?', "help");  usage();
//     OPT_END;
#define OPT_BEGIN(ctx, argc, argv) {                                    \
        getopt_init(&ctx, argc, argv);                                  \
        int _opt;                                                       \
        while ((_opt = getopt_next(&ctx)) != -1) {                      \
            const char *_long_opt = _opt == '-' ? getopt_parameter(&ctx) : 0; \
            if (1) {} else { do {} while(0)

#define OPT(s, l) continue; }                                           \
            if (_opt == s || (_opt == '-' && string_equal(_long_opt, l))) { \
                do {} while(0)

#define OPT_END continue; }                                             \
            if (_long_opt) fprintf(stderr, "Unknown option: --%s", _long_opt); \
            else           fprintf(stderr, "Unknown option: -%c" , _opt     ); \
            error("");                                                  \
            }}                                                          \
do {} while(0)
