#include <stdio.h>
#include <openssl/bn.h>

static void print_bn(const char *what, const BIGNUM *bn)
{
    char *str = BN_bn2hex(bn);
    printf("%s (hex): %s\n", what, str);
    OPENSSL_free(str);
}

int main(void)
{
    FILE *f = fopen("key.bin", "rb");
    if (!f)
        return 1;

    unsigned char buf[256];
    if (fread(buf, sizeof(buf), 1, f) != 1)
        return 1;

    BIGNUM *mod = BN_bin2bn(buf, sizeof(buf), NULL);
    if (!mod) {
        fprintf(stderr, "BN_bin2bn() failed\n");
        return 1;
    }
    print_bn("Modulus", mod);
   

    BIGNUM *exp = NULL;
    if (BN_dec2bn(&exp, "65537") == 0) {
        fprintf(stderr, "BN_dec2bn() failed\n");
        return 1;
    }
    print_bn("Exponent", exp);


    return 0;
}
