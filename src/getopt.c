#include "getopt.h"

// We could use strcmp(), but I'd rather avoid the dependency.
static int is_dash(getopt_ctx *ctx, int idx)
{
    return ctx->argv[idx][0] == '-'
        && ctx->argv[idx][1] == '\0';
}
static int is_double_dash(getopt_ctx *ctx, int idx)
{
    return ctx->argv[idx][0] == '-'
        && ctx->argv[idx][1] == '-'
        && ctx->argv[idx][2] == '\0';
}

// Pretend the argument at ctx->argv[idx] never existed.
static void forget_argument(getopt_ctx *ctx, int idx)
{
    char *tmp = ctx->argv[idx];
    while (idx > 0) {
        ctx->argv[idx] = ctx->argv[idx-1];
        idx--;
    }
    ctx->argv[0]  = tmp;
    ctx->char_idx = 0;  // point to the begining of the next argument
    ctx->argv++;
    ctx->argc--;
}

void getopt_init(getopt_ctx *ctx, int argc, char *argv[])
{
    ctx->argc     = argc - 1; // remove program name
    ctx->argv     = argv + 1; // remove program name
    ctx->argv_idx = 0;
    ctx->char_idx = 0;
}

int getopt_next(getopt_ctx *ctx)
{
    if (ctx->char_idx == 0) {
        int    idx  = ctx->argv_idx;
        char **argv = ctx->argv;
        // Search argv for the next option
        while (idx < ctx->argc &&
               (argv[idx][0] != '-' || is_dash(ctx, idx))) {
            idx++;
        }
        // No more arguments
        if (idx == ctx->argc) {
            return -1;
        }
        // End of options marker found.  No more options, Get rid of it.
        if (is_double_dash(ctx, idx)) {
            forget_argument(ctx, idx);
            return -1;
        }
        // Remember where the argument is stored
        ctx->argv_idx = idx;
    }
    // Point to the current option
    ctx->char_idx++;

    // Option has been found
    char* option_string  = ctx->argv[ctx->argv_idx] + ctx->char_idx;
    char  current_option = option_string[0];
    int   is_last        = option_string[1] == 0;
    if (is_last) {
        forget_argument(ctx, ctx->argv_idx);
    }
    return current_option;
}

char* getopt_parameter(getopt_ctx *ctx)
{
    int idx = ctx->argv_idx;
    if (idx >= ctx->argc || is_double_dash(ctx, idx)) {
        return 0; // missing option parameter
    }
    int   char_idx = ctx->char_idx == 0 ? 0 : ctx->char_idx + 1;
    char *argument = ctx->argv[idx] + char_idx;
    forget_argument(ctx, idx);
    return argument;
}
