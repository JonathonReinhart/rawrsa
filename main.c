#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libgen.h>
#include <limits.h>
#include <getopt.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "librsaconverter.h"

#define MAX_MOD_SIZE        (OPENSSL_RSA_MAX_MODULUS_BITS * CHAR_BIT)
#define DEFAULT_EXPONENT    65537ul

#define err(fmt, ...)   \
    fprintf(stderr, "%s: " fmt, appname, ##__VA_ARGS__)

#ifdef DEBUG
# define USE_DEBUG  1
#else
# define USE_DEBUG  0
#endif

#define dbg(fmt, ...)   \
    if (USE_DEBUG) fprintf(stderr, fmt, ##__VA_ARGS__)

static const char* appname;

static void print_bn(const char *what, const BIGNUM *bn)
{
#ifdef DEBUG
    char *str = BN_bn2hex(bn);
    fprintf(stderr, "%s (hex): %s\n", what, str);
    OPENSSL_free(str);
#endif
}

/**
 * OpenSSL pre-1.1 compatibility
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */

static void usage(void)
{
    fprintf(stderr, "\n"
        "Usage:\n"
        " %s [options] <modulus-file>\n"
        "\n"
        "Options:\n"
        " -e, --exponent EXP    Exponent, defaults to %lu\n"
        " -p, --privexp  FILE   Private exponent bignum file\n"
        "\n"
        "If --privexp is given, output format is a private key.\n",
        appname, DEFAULT_EXPONENT);
}

static unsigned long exponent = DEFAULT_EXPONENT;
static const char *modfile;
static const char *privexp_file;

static void parse_opts(int argc, char *argv[])
{
    int long_index = 0;
    int opt;

    static struct option long_options[] = {
        {"exponent",    required_argument,  0,  'e'},
        {"privexp",     required_argument,  0,  'p'},
        {NULL,          0,                  0,  0}
    };

    while ((opt = getopt_long(argc, argv, "e:p:",
                    long_options, &long_index)) != -1) {
        switch (opt) {
            case 'e':
                if (sscanf(optarg, "%lu", &exponent) != 1) {
                    err("Invalid exponent: \"%s\"\n", optarg);
                    exit(1);
                }
                break;

            case 'p':
                privexp_file = optarg;
                break;

            default:
                usage();
                exit(1);
                break;
        }
    }

    argv += optind;
    argc -= optind;

    if (argc < 1) {
        err("Missing argument\n");
        usage();
        exit(1);
    }
    modfile = argv[0];
}

static BIGNUM *read_bignum_file(const char *path)
{
    FILE *f = NULL;
    BIGNUM *res = NULL;
    unsigned char *buf = NULL;
    int filesize;

    /* Open */
    f = fopen(path, "rb");
    if (!f) {
        err("Failed to open \"%s\": %m\n", path);
        goto out;
    }

    /* Get file size */
    fseek(f, 0, SEEK_END);
    filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    /* Allocate buffer */
    buf = malloc(filesize);
    if (!buf) {
        err("Failed to allocate %d bytes\n", filesize);
        goto out;
    }

    /* Read file */
    if (fread(buf, 1, filesize, f) != filesize) {
        err("Failed to read %s\n", path);
        goto out;
    }

    res = BN_bin2bn(buf, filesize, NULL);
    if (!res) {
        err("BN_bin2bn() failed\n");
        goto out;
    }

out:
    if (f)
        fclose(f);
    free(buf);
    return res;
}

static bool check_rsa_sfm(const RSA *rsa)
{
    const BIGNUM *n, *e, *d;

    RSA_get0_key(rsa, &n, &e, &d);
    return CheckRsaSfmKey(n, e, d);
}

static bool expand_rsa_sfm_to_crt(RSA *rsa)
{
    const BIGNUM *n, *e, *d;
    BIGNUM *p, *q, *dp, *dq, *u;
    int rc;

    RSA_get0_key(rsa, &n, &e, &d);

    /* Set up output bignums */
    p  = BN_new();
    q  = BN_new();
    dp =  BN_new();
    dq =  BN_new();
    u  =  BN_new();

    /* Compute the RSA CRT components from the modulus, public exponent, and
     * private exponent.
     */
    rc = SfmToCrt(n, e, d,
            p, q, dp, dq, u);
    if (rc != 1) {
        err("SfmToCrt() failed\n");
        return false;
    }

    RSA_set0_factors(rsa, p, q);

    /* openssl refers to these as dmp1, dmq1, iqmp */
    RSA_set0_crt_params(rsa, dp, dq, u);

    return true;
}

int main(int argc, char *argv[])
{
    BIGNUM *mod = NULL;
    BIGNUM *privexp = NULL;

    appname = basename(argv[0]);
    parse_opts(argc, argv);

    mod = read_bignum_file(modfile);
    if (!mod) {
        return 1;
    }
    print_bn("Public modulus (n)", mod);

    if (privexp_file) {
        privexp = read_bignum_file(privexp_file);
        if (!privexp) {
            return 1;
        }
        print_bn("Private exponent (d)", privexp);
    }

    /* Parse exponent */
    BIGNUM *exp = BN_new();
    if (BN_set_word(exp, exponent) == 0) {
        err("BN_set_word() failed\n");
        return 1;
    }
    print_bn("Public exponent", exp);

    /* Create RSA key */
    RSA *rsa = RSA_new();
    if (!rsa) {
        err("RSA_new() failed\n");
        return 1;
    }
    RSA_set0_key(rsa, mod, exp, privexp);

    if (privexp) {
        /* Check the private key */
        if (!check_rsa_sfm(rsa)) {
            err("Invalid private RSA key\n");
            return 2;
        }
        dbg("RSA key consistency ok\n");

        /* Expand the private key to include factors and crt params */
        if (!expand_rsa_sfm_to_crt(rsa)) {
            err("Unable to expand RSA key\n");
            return 2;
        }

        /* Write PEM-encoded RSA private key to stdout */
        if (!PEM_write_RSAPrivateKey(stdout, rsa, NULL, NULL, 0, NULL, NULL)) {
            err("PEM_write_RSAPrivateKey() failed\n");
            return 1;
        }
    }
    else {
        /* Write PEM-encoded RSA public key to stdout */
        if (!PEM_write_RSA_PUBKEY(stdout, rsa)) {
            err("PEM_write_RSAPublicKey() failed\n");
            return 1;
        }
    }

    return 0;
}
