/*
  Benign RE challenge: license check with light obfuscation.

  Goal:
    - Reverse the binary to recover the valid license key for a given username.
    - Observe simple anti-RE tricks: inline XOR "encryption", checksum, and misleading strings.

  Usage:
    ./challenge <username> <license>

  Notes:
    - Built with -O0, no PIE, no stack protector to ease static analysis for training.
    - Intended for educational reverse engineering only.
*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void xor_bytes(char *buf, size_t len, uint8_t key) {
    for (size_t i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}

static uint32_t checksum(const char *s) {
    uint32_t h = 5381;
    for (size_t i = 0; s[i]; i++) {
        h = ((h << 5) + h) ^ (uint8_t)s[i];
    }
    return h;
}

static void derive_key(const char *user, char *out, size_t outlen) {
    uint32_t cs = checksum(user);
    // simple base charset
    const char alphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    size_t alen = strlen(alphabet);
    for (size_t i = 0; i < outlen; i++) {
        out[i] = alphabet[(cs + i * 7) % alen];
        cs ^= (uint32_t)(out[i] + i);
        cs = (cs << 3) | (cs >> 29);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) {
        puts("Usage: ./challenge <username> <license>");
        return 1;
    }
    const char *user = argv[1];
    const char *lic = argv[2];

    char derived[20] = {0};
    derive_key(user, derived, sizeof(derived) - 1);

    char check[20] = {0};
    memcpy(check, derived, sizeof(derived));
    xor_bytes(check, strlen(check), 0x5A);

    if (strncmp(lic, check, strlen(check)) == 0) {
        printf("Welcome, %s! License valid.\\n", user);
        return 0;
    } else {
        puts("Invalid license.");
        return 2;
    }
}
