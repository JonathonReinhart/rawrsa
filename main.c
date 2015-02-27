#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/bn.h>

static const char* appname;

static void print_bn(const char *what, const BIGNUM *bn)
{
    char *str = BN_bn2hex(bn);
    printf("%s (hex): %s\n", what, str);
    OPENSSL_free(str);
}

static void usage(void)
{
    fprintf(stderr, "Usage: %s modulus-file exponent\n", appname);
}

int main(int argc, char *argv[])
{
    appname = basename(argv[0]);

    if (argc < 3) {
        usage();
        exit(1);
    }

    const char *modfile = argv[1];
    const char *expstr = argv[2];

    /* Read modulus */
    FILE *mf = fopen(modfile, "rb");
    if (!mf) {
        fprintf(stderr, "%s: Failed to open \"%s\": %m\n", appname, modfile);
        return 1;
    }

    unsigned char buf[256];
    if (fread(buf, sizeof(buf), 1, mf) != 1) {
        fprintf(stderr, "%s: Failed to read %zu bytes of modulus\n", appname, sizeof(buf));
        return 1;
    }

    BIGNUM *mod = BN_bin2bn(buf, sizeof(buf), NULL);
    if (!mod) {
        fprintf(stderr, "BN_bin2bn() failed\n");
        return 1;
    }
    print_bn("Modulus", mod);
   

    BIGNUM *exp = NULL;
    if (BN_dec2bn(&exp, expstr) == 0) {
        fprintf(stderr, "BN_dec2bn() failed\n");
        return 1;
    }
    print_bn("Exponent", exp);


    return 0;
}
