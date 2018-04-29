// getopt context
typedef struct {
    // Read when getop_next() returns -1.
    // They will contain the regular arguments.
    // Order is preserved.
    int    argc;
    char **argv;

    // Private stuff. (Don't read, don't modify)
    int char_idx;
    int argv_idx;
} getopt_ctx;

// Call this first
void getopt_init(getopt_ctx *ctx, int argc, char *argv[]);

// Gives the value of the next option, or -1 if there is none left.
// Permutes the arguments as it goes so that all regular arguments
// are at the end.  Use ctx->argc and ctx->argv to loop over them.
int getopt_next(getopt_ctx *ctx);

// Return the parameter of the option we just got.
// Can be used to handle long options
char* getopt_parameter(getopt_ctx *ctx);
