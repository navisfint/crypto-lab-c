/* ==========================================================================
 *  实验 1-1  对称密码算法 AES-256-CBC（OpenSSL 3.x EVP 高层接口）
 *  -------------------------------------------------------------------------
 *  功能：
 *    1) 以固定种子值（示例 1000），用 PBKDF2-HMAC-SHA256 派生个性化的
 *       AES-256 密钥(32B) / IV(16B) / RSA 种子(32B)，保证每次运行结果一致；
 *    2) 对文件 1.txt 做 AES-256-CBC 加密 / 解密（自动 PKCS#7 填充），
 *       并逐字节比对解密结果与原文；
 *    3) 对命令行给定的十六进制输入（如 1F）加密，再把输入改动 1 个比特
 *       （1F -> 1E）后加密，统计两组密文的比特差异，观察雪崩效应。
 *  编译：build.bat aes_lab.c /Fe:aes_lab.exe
 *  运行：aes_lab.exe            全流程（文件加解密 + 十六进制对比）
 *        aes_lab.exe file 1.txt 只做文件加解密
 *        aes_lab.exe hex 1F      只做单块十六进制加密对比
 * ========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define STUDENT_ID   1000          /* 密钥派生种子（示例值，可自定义） */
#define KEY_LEN      32            /* AES-256 */
#define IV_LEN       16
#define SEED_LEN     32
#define BLOCK_SIZE   16

/*--------------------------------------------------------------------------
 * 工具函数
 *------------------------------------------------------------------------*/
static void print_hex(const char *label, const unsigned char *buf, int len)
{
    int i;
    printf("%s", label);
    for (i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 32 == 0 && i + 1 < len) printf("\n%*s", (int)strlen(label), "");
    }
    printf("\n");
}

static int read_file(const char *path, unsigned char **out, int *out_len)
{
    FILE *fp = fopen(path, "rb");
    long  size;
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    *out = (unsigned char *)malloc(size ? size : 1);
    if (!*out) { fclose(fp); return 0; }
    *out_len = (int)fread(*out, 1, size, fp);
    fclose(fp);
    return 1;
}

static int write_file(const char *path, const unsigned char *buf, int len)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return 0;
    if (len > 0) fwrite(buf, 1, len, fp);
    fclose(fp);
    return 1;
}

/* 十六进制字符串 -> 字节串；返回字节数，失败返回 -1 */
static int hex2bin(const char *hex, unsigned char *bin, int max_len)
{
    int n = 0, i;
    size_t len = strlen(hex);
    if (len % 2 != 0 || (int)(len / 2) > max_len) return -1;
    for (i = 0; i < (int)len; i += 2) {
        int hi, lo;
        char c1 = hex[i], c2 = hex[i + 1];
        hi = (c1 >= '0' && c1 <= '9') ? c1 - '0' : (c1 >= 'a' && c1 <= 'f') ? c1 - 'a' + 10
           : (c1 >= 'A' && c1 <= 'F') ? c1 - 'A' + 10 : -1;
        lo = (c2 >= '0' && c2 <= '9') ? c2 - '0' : (c2 >= 'a' && c2 <= 'f') ? c2 - 'a' + 10
           : (c2 >= 'A' && c2 <= 'F') ? c2 - 'A' + 10 : -1;
        if (hi < 0 || lo < 0) return -1;
        bin[n++] = (unsigned char)((hi << 4) | lo);
    }
    return n;
}

/*--------------------------------------------------------------------------
 * (1) 个性化密钥生成函数
 *     以固定种子为口令、PBKDF2-HMAC-SHA256 派生 32B 密钥 + 16B IV + 32B RSA 种子
 *------------------------------------------------------------------------*/
void generate_personalized_keys_evp(unsigned char* aes_key,
                                    unsigned char* aes_iv,
                                    unsigned char* rsa_seed)
{
    char          pass[32];
    char          salt[32];
    unsigned char material[KEY_LEN + IV_LEN + SEED_LEN];

    snprintf(pass, sizeof(pass), "STUDENT-%d", STUDENT_ID);
    snprintf(salt, sizeof(salt), "CryptoLab-1-1-%d", STUDENT_ID);

    /* 口令 -> 80 字节密钥材料，再切分为 key / iv / rsa_seed */
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass),
                          (const unsigned char *)salt, (int)strlen(salt),
                          100000, EVP_sha256(),
                          (int)sizeof(material), material) != 1) {
        fprintf(stderr, "PBKDF2 failed\n");
        exit(1);
    }
    memcpy(aes_key,   material,                KEY_LEN);
    memcpy(aes_iv,    material + KEY_LEN,      IV_LEN);
    memcpy(rsa_seed,  material + KEY_LEN + IV_LEN, SEED_LEN);
}

/*--------------------------------------------------------------------------
 * (2) AES-256-CBC 加密：单次调用完成，自动 PKCS#7 填充
 *------------------------------------------------------------------------*/
int evp_aes_cbc_encrypt(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0, total = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) goto err;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) goto err;
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/*--------------------------------------------------------------------------
 * (3) AES-256-CBC 解密：自动校验并去除 PKCS#7 填充
 *     返回 -1 一般错误，-2 填充校验失败（密钥错误或密文被篡改）
 *------------------------------------------------------------------------*/
int evp_aes_cbc_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len = 0, total = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) goto err;
    total = len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -2;                       /* 填充校验失败 */
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    return total;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/*--------------------------------------------------------------------------
 * 统计两个等长缓冲区中不同的比特位数
 *------------------------------------------------------------------------*/
static int bit_difference(const unsigned char *a, const unsigned char *b, int len)
{
    int i, bits = 0;
    for (i = 0; i < len; i++) {
        unsigned char x = (unsigned char)(a[i] ^ b[i]);
        while (x) { bits += x & 1; x >>= 1; }
    }
    return bits;
}

/*--------------------------------------------------------------------------
 * 任务 A：对文件 1.txt 加密 / 解密
 *------------------------------------------------------------------------*/
static int task_file(const char *path)
{
    unsigned char  key[KEY_LEN], iv[IV_LEN], seed[SEED_LEN];
    unsigned char *plain = NULL, *cipher = NULL, *back = NULL;
    int  plain_len = 0, cipher_len = 0, back_len = 0;
    char out_enc[512], out_dec[512];
    int  i, diff = 0;

    printf("==================================================================\n");
    printf("  Task A : AES-256-CBC encrypt / decrypt file  \"%s\"\n", path);
    printf("==================================================================\n");

    generate_personalized_keys_evp(key, iv, seed);
    printf("[1] Personalized key material (seed = STUDENT_ID %d, PBKDF2-SHA256)\n", STUDENT_ID);
    print_hex("    AES-256 KEY (32B) : ", key, KEY_LEN);
    print_hex("    AES IV      (16B) : ", iv, IV_LEN);
    print_hex("    RSA SEED    (32B) : ", seed, SEED_LEN);

    if (!read_file(path, &plain, &plain_len)) {
        printf("    [ERROR] cannot open %s\n", path);
        return 0;
    }
    printf("\n[2] Plain file  : %s  (%d bytes)\n", path, plain_len);
    printf("    ------------------------------------------------------------\n");
    fwrite(plain, 1, plain_len, stdout);
    printf("\n    ------------------------------------------------------------\n");

    cipher = (unsigned char *)malloc(plain_len + BLOCK_SIZE);
    if (!cipher) return 0;
    cipher_len = evp_aes_cbc_encrypt(plain, plain_len, key, iv, cipher);
    if (cipher_len < 0) { printf("    [ERROR] encryption failed\n"); return 0; }
    printf("\n[3] Ciphertext  : %d bytes  (plaintext %d + PKCS#7 padding %d)\n",
           cipher_len, plain_len, cipher_len - plain_len);
    print_hex("    HEX : ", cipher, cipher_len);
    write_file("1.txt.enc", cipher, cipher_len);
    printf("    saved to 1.txt.enc\n");

    back = (unsigned char *)malloc(cipher_len + 1);
    back_len = evp_aes_cbc_decrypt(cipher, cipher_len, key, iv, back);
    if (back_len < 0) {
        printf("    [ERROR] decryption failed, code = %d\n", back_len);
        return 0;
    }
    back[back_len] = '\0';
    printf("\n[4] Decrypted   : %d bytes\n", back_len);
    printf("    ------------------------------------------------------------\n");
    fwrite(back, 1, back_len, stdout);
    printf("\n    ------------------------------------------------------------\n");
    write_file("1.txt.dec", back, back_len);

    printf("\n[5] Integrity check (byte by byte)\n");
    printf("    original  : %d bytes\n", plain_len);
    printf("    decrypted : %d bytes\n", back_len);
    if (plain_len == back_len) {
        for (i = 0; i < plain_len; i++) if (plain[i] != back[i]) diff++;
        printf("    mismatched bytes = %d  ->  %s\n", diff, diff == 0 ? "IDENTICAL" : "DIFFERENT");
    } else {
        printf("    length mismatch -> DIFFERENT\n");
    }

    /* 反面验证：密钥被改 1 比特，解密应报填充错误 */
    printf("\n[6] Negative test : flip 1 bit of the key and decrypt again\n");
    key[0] ^= 0x01;
    i = evp_aes_cbc_decrypt(cipher, cipher_len, key, iv, back);
    printf("    decrypt() returned %d  ->  %s\n", i,
           i == -2 ? "PKCS#7 padding check failed (tampered / wrong key)" :
           i < 0   ? "generic error" : "unexpected success");
    key[0] ^= 0x01;

    snprintf(out_enc, sizeof(out_enc), "1.txt.enc");
    snprintf(out_dec, sizeof(out_dec), "1.txt.dec");
    free(plain); free(cipher); free(back);
    return 1;
}

/*--------------------------------------------------------------------------
 * 任务 B：十六进制输入单块加密 + 单比特改动对比
 *------------------------------------------------------------------------*/
static int task_hex(const char *hex_in)
{
    unsigned char  key[KEY_LEN], iv[IV_LEN], seed[SEED_LEN];
    unsigned char  in1[64], in2[64], c1[128], c2[128];
    int  n1, n2, len1, len2;
    char hex2[128];
    int  i, bits;

    printf("\n==================================================================\n");
    printf("  Task B : encrypt a hex input, then flip 1 bit and compare\n");
    printf("==================================================================\n");

    generate_personalized_keys_evp(key, iv, seed);
    printf("[1] Key / IV reused (same personalized material as Task A)\n");
    print_hex("    KEY : ", key, KEY_LEN);
    print_hex("    IV  : ", iv, IV_LEN);

    n1 = hex2bin(hex_in, in1, sizeof(in1));
    if (n1 <= 0) { printf("    [ERROR] bad hex input: %s\n", hex_in); return 0; }

    /* 构造"改动 1 个比特"的输入：最低位取反 */
    memcpy(in2, in1, n1);
    in2[n1 - 1] ^= 0x01;
    n2 = n1;
    for (i = 0; i < n2; i++) sprintf(hex2 + 2 * i, "%02X", in2[i]);

    len1 = evp_aes_cbc_encrypt(in1, n1, key, iv, c1);
    len2 = evp_aes_cbc_encrypt(in2, n2, key, iv, c2);
    if (len1 < 0 || len2 < 0) { printf("    [ERROR] encryption failed\n"); return 0; }

    printf("\n[2] Input #1 : 0x%s   (%d byte, %d bit)\n", hex_in, n1, n1 * 8);
    print_hex("    ciphertext : ", c1, len1);
    printf("    cipher len = %d bytes\n", len1);

    printf("\n[3] Input #2 : 0x%s   (last bit flipped, 1F -> 1E style)\n", hex2);
    print_hex("    ciphertext : ", c2, len2);
    printf("    cipher len = %d bytes\n", len2);

    bits = bit_difference(c1, c2, len1 < len2 ? len1 : len2);
    printf("\n[4] Comparison\n");
    printf("    plaintext  : %2d bit, changed %d bit\n", n1 * 8, 1);
    printf("    ciphertext : %2d bit, changed %d bit  (%.1f%%)\n",
           len1 * 8, bits, 100.0 * bits / (len1 * 8));
    for (i = 0; i < len1; i++) {
        unsigned char x = (unsigned char)(c1[i] ^ c2[i]);
        printf("    %02d:%02X^%02X=%02X%s", i, c1[i], c2[i], x,
               ((i + 1) % 4 == 0) ? "\n" : "   ");
    }
    return 1;
}

int main(int argc, char *argv[])
{
    const char *mode = (argc > 1) ? argv[1] : "all";

    printf("#################################################################\n");
    printf("#  Lab 1-1  AES-256-CBC with OpenSSL EVP   (STUDENT_ID = %d)\n", STUDENT_ID);
    printf("#  %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("#################################################################\n");

    if (strcmp(mode, "file") == 0) {
        return task_file(argc > 2 ? argv[2] : "1.txt") ? 0 : 1;
    }
    if (strcmp(mode, "hex") == 0) {
        return task_hex(argc > 2 ? argv[2] : "1F") ? 0 : 1;
    }

    if (!task_file("1.txt")) return 1;
    if (!task_hex("1F")) return 1;

    printf("\n==================================================================\n");
    printf("  All tasks finished.\n");
    printf("==================================================================\n");
    return 0;
}
