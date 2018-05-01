#include "monocypher.h"
#include "sha512.h"
#include "getopt.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define            BLOCK_SIZE     4096
static const int   BLAKE2B      = 0;
static const int   SHA512       = 1;
static const char* usage_string =
    "Usage: hash [OPTION]... [FILES]... \n"
    "With no FILES, or when FILES is -, read standard input\n"
    "\n"
    "-a --algorithm      blake2b or sha512 (blake2b by default)\n"
    "-l --digest-length  digest length (8-512 bits, 512 bits by default)\n"
    "-k --key            secret key (in hexadecimal, no key by default)\n"
    "-t --tag            create a BSD-style checksum\n"
    "-? --help           display this help and exit\n"
    "\n";

void panic(const char *error)
{
    fprintf(stderr, "%s\n%s", error, usage_string);
    exit(1);
}

int parse_algorithm(getopt_ctx *ctx)
{
    const char *algorithm = getopt_parameter(ctx);
    if (algorithm == 0) {
        panic("-a: unspecified algorithm");
    }
    if (string_equal(algorithm, "blake2b")) { return BLAKE2B; }
    if (string_equal(algorithm, "sha512" )) { return SHA512;  }
    panic("-a: algorithm must be blake2b or sha512");
    return -1; // impossible
}

int parse_key(getopt_ctx *ctx, uint8_t key[64])
{
    int key_size = read_buffer(key, 64, getopt_parameter(ctx));
    switch (key_size) {
    case -1: panic("--key: unspecified key"             );
    case -2: panic("--key: key too long"                );
    case -3: panic("--key: key has odd number of digits");
    case -4: panic("--key: key contains non-hex digits" );
    default:;
    }
    return key_size;
}

size_t parse_digest_size(getopt_ctx *ctx)
{
    const char *length = getopt_parameter(ctx);
    if (length == 0) {
        panic("-l: missing digest size");
    }
    int l = int_of_string(length);
    if (l == -1         ) panic("-l: digest size must be a decimal integer."  );
    if (l == -2         ) panic("-l: digest size out of range (8 - 512 bits)" );
    if (l < 8 || l > 512) panic("-l: digest size out of range (8 - 512 bits)" );
    if (l % 8 != 0      ) panic("-l: digest size must be a multiple of 8 bits");
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

    // print
    if (!tag) {
        print_buffer(digest, digest_size);
        printf(" %s\n", file_name);
    } else {
        static const char *algorithm_names[] = { "BLAKE2b", "SHA512" };
        printf("%s", algorithm_names[algorithm]);
        if (digest_size != 64) {
            printf("-%u", (unsigned)digest_size * 8);
        }
        printf(" (%s) = \n", file_name);
        print_buffer(digest, digest_size);
    }
}

// Puts a short and long option together
#define OPT(s, l) if (opt == s ||                                       \
                      (opt == '-' && string_equal(getopt_parameter(&ctx),l)))

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
        OPT     ('t', "tag"        ) tag         = 1;
        else OPT('a', "algorithm"  ) algorithm   = parse_algorithm  (&ctx     );
        else OPT('l', "digest-size") digest_size = parse_digest_size(&ctx     );
        else OPT('k', "key"        ) key_size    = parse_key        (&ctx, key);
        else OPT('?', "help"       ) { printf("%s", usage_string);  return 0; }
        else {
            fprintf(stderr, "Unknown option: -%c\n", opt);
            fprintf(stderr, "%s", usage_string);
            exit(1);
        }
    }
    if (algorithm == SHA512) {
        if (key_size    !=  0) panic("sha512 does not use secret keys");
        if (digest_size != 64) panic("sha512 digests are 512 bits");
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
