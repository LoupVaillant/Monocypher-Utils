#include "monocypher.h"
#include "sha512.h"
#include "getopt.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

#define BLOCK_SIZE 4096

int is_between(char c, char start, char end)
{
    return c >= start && c <= end;
}

int int_of_digit(char c)
{
    return is_between(c, '0', '9') ? c - '0' : -1;
}

int int_of_hex(char c)
{
    return is_between(c, '0', '9') ? c - '0'
        :  is_between(c, 'a', 'f') ? c - 'a'
        :  is_between(c, 'A', 'F') ? c - 'A'
        :  -1;
}

char hex_of_int(int i)
{
    return i < 10 ? '0' + i : 'a' + (i - 10);
}

size_t string_length(const char *s)
{
    if (s == 0) { return -1u; }
    size_t i = 0;
    while(*s != '\0') { i++; s++; }
    return i;
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

void usage(const char *error)
{
    int exit_code = error ? 1 : 0;
    if (error) {
        fprintf(stderr, "%s\n", error);
    }
    printf("TODO usage message\n");
    exit(exit_code);
}

static const int   BLAKE2B = 0;
static const int   SHA512  = 1;
static const char *algorithm_names[] = { "BLAKE2b", "SHA512" };

int parse_algorithm(getopt_ctx *ctx)
{
    const char *algorithm = getopt_parameter(ctx);
    if (algorithm == 0) {
        usage("-a: unspecified algorithm");
    }
    if (strcmp(algorithm, "blake2b") == 0) { return BLAKE2B; }
    if (strcmp(algorithm, "sha512" ) == 0) { return SHA512;  }
    usage("-a: algorithm must be blake2b or sha512");
    return -1; // impossible
}

int parse_key(getopt_ctx *ctx, uint8_t key[64])
{
    const char *key_str  = getopt_parameter(ctx);
    size_t      key_size = string_length(key_str);
    if (key_str      ==  0) usage("--key: unspecified key"             );
    if (key_size     > 128) usage("--key: key too long"                );
    if (key_size % 2 !=  0) usage("--key: key has odd number of digits");
    key_size /= 2;
    for (size_t i = 0; i < key_size; i += 2) {
        int msb = int_of_hex(key_str[i  ]);
        int lsb = int_of_hex(key_str[i+1]);
        if (msb == -1 || lsb == -1) {
            usage("--key: key contains non-hex digits");
        }
        key[i/2] = lsb + (msb << 4);
    }
    return key_size;
}

size_t parse_digest_size(getopt_ctx *ctx)
{
    const char *length = getopt_parameter(ctx);
    if (length == 0) {
        usage("-l: missing digest size");
    }
    int l = int_of_string(length);
    if (l == -1         ) usage("-l: digest size must be a decimal integer."  );
    if (l == -2         ) usage("-l: digest size out of range (8 - 512 bits)" );
    if (l < 8 || l > 512) usage("-l: digest size out of range (8 - 512 bits)" );
    if (l % 8 != 0      ) usage("-l: digest size must be a multiple of 8 bits");
    return (size_t)l / 8;
}

void hash_input(int algorithm, int tag, FILE *input, const char *file_name,
                size_t digest_size, const uint8_t *key, size_t key_size)
{
    // init
    crypto_blake2b_ctx blake2b_ctx;
    crypto_sha512_ctx  sha512_ctx;
    if (algorithm == BLAKE2B) {
        crypto_blake2b_general_init(&blake2b_ctx, digest_size, key, key_size);
    }
    if (algorithm == SHA512) {
        crypto_sha512_init(&sha512_ctx);
    }

    // update
    uint8_t block[BLOCK_SIZE];
    while (!feof(input) && !ferror(input)) {
        size_t nb_read = fread(block, 1, BLOCK_SIZE, input);
        if (algorithm == BLAKE2B) {
            crypto_blake2b_update(&blake2b_ctx, block, nb_read);
        }
        if (algorithm == SHA512 ) {
            crypto_sha512_update (&sha512_ctx , block, nb_read);
        }
    }
    if (ferror(input)) {
        fprintf(stderr, "An error occured while reading input.\n");
        exit(2);
    }

    // final
    uint8_t digest[64];
    if (algorithm == BLAKE2B) { crypto_blake2b_final(&blake2b_ctx, digest); }
    if (algorithm == SHA512 ) { crypto_sha512_final (&sha512_ctx , digest); }

    // to string
    char digest_string[129];
    digest_string[digest_size * 2] = '\0';
    for (size_t i = 0; i < digest_size; i++) {
        digest_string[i*2    ] = hex_of_int(digest[i] >> 4);  // msb
        digest_string[i*2 + 1] = hex_of_int(digest[i] & 0xf); // lsb
    }

    // print
    if (tag) {
        printf("%s (%s) = %s\n",
               algorithm_names[algorithm], file_name, digest_string);
    } else {
        printf("%s %s\n", digest_string, file_name);
    }
}

int main(int argc, char* argv[])
{
    int     algorithm   = BLAKE2B;
    int     tag         = 0;
    uint8_t key[64];
    size_t  key_size    = 0;
    size_t  digest_size = 64;

    // Parse and validate arguments
    getopt_ctx ctx;
    getopt_init(&ctx, argc, argv);
    int opt;
    while ((opt = getopt_next(&ctx)) != -1) {
        switch (opt) {
        case 'a': algorithm   = parse_algorithm  (&ctx     ); break;
        case 'l': digest_size = parse_digest_size(&ctx     ); break;
        case 'k': key_size    = parse_key        (&ctx, key); break;
        case '?': usage(0);
        case '-': {
            char *option = getopt_parameter(&ctx);
            if      (!strcmp(option, "tag" )) tag      = 1;
            else if (!strcmp(option, "key" )) key_size = parse_key(&ctx, key);
            else if (!strcmp(option, "help")) usage(0);
        } break;
        default: usage("Unknown option");
        }
    }
    if (algorithm == SHA512) {
        if (key_size    !=  0) usage("sha512 doesn't have a key"  );
        if (digest_size != 64) usage("sha512 digests are 512 bits");
    }

    // parse input from stdin if no file is given
    if (ctx.argc == 0) {
        if(freopen(0, "rb", stdin) != stdin) {
            perror("Could not reopen standard input in binary mode");
            exit(2);
        }
        hash_input(algorithm, tag, stdin, "-", digest_size, key, key_size);
    }

    // Read each input file in succession (if any)
    for (int i = 0; i < ctx.argc; i++) {
        FILE *input = fopen(ctx.argv[i], "rb");
        if (input == 0) {
            fprintf(stderr, "Could not open \"%s\": ", ctx.argv[i]);
            perror(0);
            exit(2);
        }
        hash_input(algorithm, tag, input, ctx.argv[i],
                   digest_size, key, key_size);
        if (fclose(input)) {
            fprintf(stderr, "Could not close \"%s\": ", ctx.argv[i]);
            perror(0);
            exit(2);
        }
    }
    return 0;
}
