#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

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

#define err(fmt, ...)   \
    fprintf(stderr, "%s: " fmt, appname, ##__VA_ARGS__)

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

    unsigned char buf[256];
    if (fread(buf, sizeof(buf), 1, mf) != 1) {
        err("Failed to read %zu bytes of modulus\n", sizeof(buf));
        return 1;
    }

    fclose(mf);

    BIGNUM *mod = BN_bin2bn(buf, sizeof(buf), NULL);
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

    /* Write RSA key to a file */
    FILE *rpk = fopen("public_key.pem", "wb");
    if (!rpk) {
        err("Failed to open public key file");
        return 1;
    }

    if (!PEM_write_RSAPublicKey(rpk, rsa)) {
        err("PEM_write_RSAPublicKey() failed\n");
        return 1;
    }

    fclose(rpk);

    return 0;
}
