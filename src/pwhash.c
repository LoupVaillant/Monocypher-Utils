#include "monocypher.h"
#include "getopt.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bsd/readpassphrase.h>

static vector parse_key(getopt_ctx *ctx) {
    vector key;
    int code = read_vector(&key, getopt_parameter(ctx));
    if (code == -1) error("unspecified key"             );
    if (code == -2) error("key too long"                );
    if (code == -3) error("key has odd number of digits");
    if (code == -4) error("key contains non-hex digits" );
    return key;
}

static vector parse_ad (getopt_ctx *ctx)
{
    vector ad;
    int code = read_vector(&ad, getopt_parameter(ctx));
    if (code == -1) error("unspecified additional data"             );
    if (code == -2) error("additional data too long"                );
    if (code == -3) error("additional data has odd number of digits");
    if (code == -4) error("additional data contains non-hex digits" );
    return ad;
}

static int parse_digest(getopt_ctx *ctx)
{
    int l = int_of_string(getopt_parameter(ctx));
    if (l == -1) error("unspecified digest size"              );
    if (l == -2) error("digest size is not a decimal integer.");
    if (l == -3) error("digest size too big"                  );
    if (l  <  4) error("digest size too small (>= 4)"         );
    return l;
}

static int parse_kib(getopt_ctx *ctx)
{
    int l = int_of_string(getopt_parameter(ctx));
    if (l == -1) error("unspecified number of kilobytes"              );
    if (l == -2) error("number of kilobytes is not a decimal integer.");
    if (l == -3) error("too many kilobytes"                           );
    if (l  <  8) error("not enough kilobytes (>= 8)"                  );
    return l;
}

static int parse_nb_it(getopt_ctx *ctx)
{
    int l = int_of_string(getopt_parameter(ctx));
    if (l == -1) error("unspecified number of iterations"               );
    if (l == -2) error("number of iterations is not  a decimal integer.");
    if (l == -3) error("too many iterations"                            );
    return l;
}

static vector parse_salt(getopt_ctx *ctx)
{
    if (ctx->argc == 0) error("Missing salt"      );
    if (ctx->argc  < 1) error("Too many arguments");
    vector salt;
    int code = read_vector(&salt, ctx->argv[0]);
    if (code     == -2)  error("salt too long"                );
    if (code     == -3)  error("salt has odd number of digits");
    if (code     == -4)  error("salt contains non-hex digits" );
    if (salt.size <  8)  error("Salt too short"               );
    return salt;
}

int main(int argc, char* argv[])
{
    size_t   digest_size   = 64;
    uint32_t nb_iterations = 3;
    uint32_t nb_kibybytes  = 102400; // 100 Mib
    vector   key           = new_vector();
    vector   ad            = new_vector();
    int      rpp_flags     = 0;

    set_usage_string(
        "Usage: pwhash [OPTION]... salt\n"
        "Read the password from standard input\n"
        "The salt must be at least 8 bytes long (16 hex digits)\n"
        "\n"
        "-l --digest-size      digest length in bytes (32 bytes by default)\n"
        "-t --nb-iterations    number of iterations (default 3)\n"
        "-m --nb-kilobytes     memory usage in KiB (default 100MiB)\n"
        "-k --key              secret key (hexadecimal, default none)\n"
        "-a --additional-data  additionnal data (hexadecimal, default none)\n"
        "-i --stdin            read password from stdin"
        "-? --help             display this help and exit\n");

    // Parse and validate arguments
    getopt_ctx ctx;
    OPT_BEGIN(ctx, argc, argv);
    OPT('l', "digest-size"    );  digest_size   = parse_digest(&ctx);
    OPT('t', "nb-iterations"  );  nb_iterations = parse_nb_it (&ctx);
    OPT('k', "nb-kilobytes"   );  nb_kibybytes  = parse_kib   (&ctx);
    OPT('k', "key"            );  key           = parse_key   (&ctx);
    OPT('a', "additional-data");  ad            = parse_ad    (&ctx);
    OPT('i', "stdin"          );  rpp_flags    |= RPP_STDIN;
    OPT('?', "help"           );  usage();
    OPT_END;
    vector   salt      = parse_salt(&ctx);
    size_t   work_size = 1024 * nb_kibybytes;
    void    *work_area = alloc(work_size);
    uint8_t *digest    = alloc(digest_size);

    // read password
    if (readpassphrase("Passphrase: ", work_area, work_size, rpp_flags) == 0) {
        panic("Could not read password");
    }
    size_t password_size = strlen(work_area);

    // hash password
    crypto_argon2i_general(digest, digest_size,
                           work_area, nb_kibybytes,
                           nb_iterations,
                           work_area  , password_size,
                           salt.buffer, salt.size,
                           key .buffer, key .size,
                           ad  .buffer, ad  .size);

    // free resources
    free(work_area);
    free_vector(&key );
    free_vector(&ad  );
    free_vector(&salt);

    // print password
    print_buffer(digest, digest_size);
    printf("\n");

    return 0;
}
