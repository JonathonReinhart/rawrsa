#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#ifndef MAX_MOD_SIZE
#define MAX_MOD_SIZE    0x1000
#endif

#define err(fmt, ...)   \
    fprintf(stderr, "%s: " fmt, appname, ##__VA_ARGS__)

static const char* appname;

static void print_bn(const char *what, const BIGNUM *bn)
{
#ifdef DEBUG
    char *str = BN_bn2hex(bn);
    printf("%s (hex): %s\n", what, str);
    OPENSSL_free(str);
#endif
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
        err("Failed to open \"%s\": %m\n", modfile);
        return 1;
    }

    unsigned char buf[MAX_MOD_SIZE];
    size_t n;
    if ((n = fread(buf, 1, sizeof(buf), mf)) == 0) {
        err("Failed to read %zu bytes of modulus\n", sizeof(buf));
        return 1;
    }
    if (n == sizeof(buf) && !feof(mf)) {
        err("Warning: modulus truncated to maximum size (%zu bytes)\n",
                sizeof(buf));
    }

    fclose(mf);

    BIGNUM *mod = BN_bin2bn(buf, n, NULL);
    if (!mod) {
        err("BN_bin2bn() failed\n");
        return 1;
    }
    print_bn("Modulus", mod);
   

    /* Parse exponent */
    BIGNUM *exp = NULL;
    if (BN_dec2bn(&exp, expstr) == 0) {
        err("BN_dec2bn() failed\n");
        return 1;
    }
    print_bn("Exponent", exp);

    /* Create RSA key */
    RSA *rsa = RSA_new();
    if (!rsa) {
        err("RSA_new() failed\n");
        return 1;
    }
    rsa->e = exp;
    rsa->n = mod;

    /* Write PEM-encoded RSA public key to stdout */
    if (!PEM_write_RSAPublicKey(stdout, rsa)) {
        err("PEM_write_RSAPublicKey() failed\n");
        return 1;
    }

    return 0;
}
