#include "monocypher.h"
#include "sha512.h"
#include "getopt.h"
#include "utils.h"
#include <stdio.h>

#define          BLOCK_SIZE 4096
static const int BLAKE2B = 0;
static const int SHA512  = 1;

static int parse_algorithm(getopt_ctx *ctx)
{
    const char *algorithm = getopt_parameter(ctx);
    if (algorithm == 0) {
        error("unspecified algorithm");
    }
    if (string_equal(algorithm, "blake2b")) { return BLAKE2B; }
    if (string_equal(algorithm, "sha512" )) { return SHA512;  }
    error("algorithm must be blake2b or sha512");
    return -1; // impossible
}

static int parse_key(getopt_ctx *ctx, uint8_t key[64])
{
    int key_size = read_buffer(key, 64, getopt_parameter(ctx));
    switch (key_size) {
    case -1: error("unspecified key"             );
    case -2: error("key too long"                );
    case -3: error("key has odd number of digits");
    case -4: error("key contains non-hex digits" );
    default:;
    }
    return key_size;
}

static size_t parse_digest_size(getopt_ctx *ctx)
{
    const char *length = getopt_parameter(ctx);
    if (length == 0) {
        error("missing digest size");
    }
    int l = int_of_string(length);
    if (l == -1         ) error("digest size must be a decimal integer."  );
    if (l == -2         ) error("digest size out of range (8 - 512 bits)" );
    if (l < 8 || l > 512) error("digest size out of range (8 - 512 bits)" );
    if (l % 8 != 0      ) error("digest size must be a multiple of 8 bits");
    return (size_t)l / 8;
}

// generic hash update and final
#define HASH(name)                                                      \
    while (!feof(input) && !ferror(input)) {                            \
        size_t nb_read = fread(block, 1, BLOCK_SIZE, input);            \
        crypto_##name##_update(&name##_ctx, block, nb_read);            \
    }                                                                   \
    if (ferror(input)) { panic("An error occured while reading input"); } \
    crypto_##name##_final(&name##_ctx, digest)

void hash_input(int algorithm, int tag, FILE *input, const char *file_name,
                size_t digest_size, const uint8_t *key, size_t key_size)
{
    uint8_t digest[64];
    uint8_t block[BLOCK_SIZE];
    if (algorithm == BLAKE2B) {
        crypto_blake2b_ctx blake2b_ctx;
        crypto_blake2b_general_init(&blake2b_ctx, digest_size, key, key_size);
        HASH(blake2b);
    }
    if (algorithm == SHA512) {
        crypto_sha512_ctx  sha512_ctx;
        crypto_sha512_init(&sha512_ctx);
        HASH(sha512);
    }

    if (!tag) {
        print_buffer(digest, digest_size);
        printf(" %s\n", file_name);
    } else {
        if (algorithm == BLAKE2B) printf("BLAKE2b");
        if (algorithm == SHA512 ) printf("SHA512" );
        if (digest_size != 64) {
            printf("-%u", (unsigned)digest_size * 8);
        }
        printf(" (%s) = ", file_name);
        print_buffer(digest, digest_size);
        printf("\n");
    }
}

int main(int argc, char* argv[])
{
    int     algorithm   = BLAKE2B;
    int     tag         = 0;
    uint8_t key[64];
    size_t  key_size    = 0;
    size_t  digest_size = 64;

    set_usage_string(
        "Usage: hash [OPTION]... [FILE]... \n"
        "With no FILE, or when FILE is -, read standard input\n"
        "\n"
        "-a --algorithm      blake2b or sha512 (blake2b by default)\n"
        "-l --digest-length  digest length (8-512 bits, 512 bits by default)\n"
        "-k --key            secret key (in hexadecimal, no key by default)\n"
        "-t --tag            create a BSD-style checksum\n"
        "-? --help           display this help and exit\n");

    // Parse and validate arguments
    getopt_ctx ctx;
    getopt_init(&ctx, argc, argv);
    int opt;
    while ((opt = getopt_next(&ctx)) != -1) {
        const char *long_opt = opt == '-' ? getopt_parameter(&ctx) : 0;
#define OPT(s, l) if (opt == s || (opt == '-' && string_equal(long_opt, l)))
        OPT     ('t', "tag"        ) tag         = 1;
        else OPT('a', "algorithm"  ) algorithm   = parse_algorithm  (&ctx     );
        else OPT('l', "digest-size") digest_size = parse_digest_size(&ctx     );
        else OPT('k', "key"        ) key_size    = parse_key        (&ctx, key);
        else OPT('?', "help"       ) usage();
        else {
            if (long_opt) fprintf(stderr, "Unknown option: --%s", long_opt);
            else          fprintf(stderr, "Unknown option: -%c" , opt     );
            error("");
        }
    }
    if (algorithm == SHA512) {
        if (key_size    !=  0) error("sha512 does not use secret keys");
        if (digest_size != 64) error("sha512 digests are 512 bits");
    }

    // parse input from stdin if no file is given
    if (ctx.argc == 0) {
        if(freopen(0, "rb", stdin) != stdin) {
            panic("Could not reopen standard input in binary mode");
        }
        hash_input(algorithm, tag, stdin, "-", digest_size, key, key_size);
    }

    // Read each input file in succession (if any)
    for (int i = 0; i < ctx.argc; i++) {
        FILE *input = fopen(ctx.argv[i], "rb");
        if (input == 0) {
            fprintf(stderr, "Could not open \"%s\": ", ctx.argv[i]);
            panic(0);
        }
        hash_input(algorithm, tag, input, ctx.argv[i],
                   digest_size, key, key_size);
        if (fclose(input)) {
            fprintf(stderr, "Could not close \"%s\": ", ctx.argv[i]);
            panic(0);
        }
    }
    return 0;
}
