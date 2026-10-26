/* ==========================================================================
 *  实验 1-3  Hash 算法 SHA-256（OpenSSL 3.x EVP 高层接口）
 *  -------------------------------------------------------------------------
 *  功能：
 *    1) evp_sha256_hash()：一次喂入内存数据计算 32 字节摘要；
 *    2) 文件摘要：按 4 KB 分块 EVP_DigestUpdate，适用于任意大小文件；
 *    3) 篡改检测：改动 1.txt 的 1 个比特后重新求摘要，统计差异比特数；
 *    4) 定长性：不同长度输入 -> 摘要长度恒为 32 字节；
 *    5) 计算文件摘要并与 Windows 数字签名配合（见报告中 sigverif 部分）。
 *  编译：cl -nologo -utf-8 -O2 -MD -Fe:sha_lab.exe sha_lab.c -link libcrypto.lib
 * ========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define HASH_LEN 32
#define CHUNK    4096

static void print_digest(const char *label, const unsigned char *h, size_t n)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < n; i++) printf("%02x", h[i]);
    printf("\n");
}

static void print_digest_upper(const char *label, const unsigned char *h, size_t n)
{
    size_t i;
    printf("%s", label);
    for (i = 0; i < n; i++) printf("%02X", h[i]);
    printf("\n");
}

static char printable(unsigned char c)
{
    return (c >= 0x20 && c < 0x7F) ? (char)c : '.';
}

/*--------------------------------------------------------------------------
 * (1) EVP SHA-256 哈希函数（单次喂入）
 *------------------------------------------------------------------------*/
int evp_sha256_hash(const unsigned char* data,
                    size_t data_len,
                    unsigned char* hash,
                    size_t* hash_len)
{
    EVP_MD_CTX *md_ctx;
    unsigned int out_len = 0;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return 0;

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1)       goto fail;
    if (EVP_DigestUpdate(md_ctx, data, data_len) != 1)            goto fail;
    if (EVP_DigestFinal_ex(md_ctx, hash, &out_len) != 1)          goto fail;

    *hash_len = (size_t)out_len;
    EVP_MD_CTX_free(md_ctx);
    return 1;
fail:
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

/*--------------------------------------------------------------------------
 * (2) 文件摘要：分块 Update，适合大文件，内存占用恒定
 *------------------------------------------------------------------------*/
int sha256_file(const char *path, unsigned char *hash, size_t *hash_len, long *file_size)
{
    EVP_MD_CTX   *md_ctx;
    unsigned char buf[CHUNK];
    size_t n;
    unsigned int out_len = 0;
    FILE *fp = fopen(path, "rb");
    long total = 0;

    if (!fp) return 0;
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) { fclose(fp); return 0; }
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) goto fail;

    while ((n = fread(buf, 1, CHUNK, fp)) > 0) {
        total += (long)n;
        if (EVP_DigestUpdate(md_ctx, buf, n) != 1) goto fail;
    }
    if (EVP_DigestFinal_ex(md_ctx, hash, &out_len) != 1) goto fail;

    fclose(fp);
    EVP_MD_CTX_free(md_ctx);
    *hash_len  = (size_t)out_len;
    *file_size = total;
    return 1;
fail:
    fclose(fp);
    EVP_MD_CTX_free(md_ctx);
    return 0;
}

static int bit_difference(const unsigned char *a, const unsigned char *b, size_t len)
{
    size_t i;
    int bits = 0;
    for (i = 0; i < len; i++) {
        unsigned char x = (unsigned char)(a[i] ^ b[i]);
        while (x) { bits += x & 1; x >>= 1; }
    }
    return bits;
}

int main(void)
{
    unsigned char h1[HASH_LEN], h2[HASH_LEN];
    size_t hlen = 0, hlen2 = 0;
    long   fsize = 0;
    unsigned char *data = NULL;
    long   n;
    FILE  *fp;
    int    i;

    printf("#################################################################\n");
    printf("#  Lab 1-3  SHA-256 with OpenSSL EVP\n");
    printf("#  %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("#################################################################\n");

    /* ---------- 1. 定长性：空串 / 短串 / 长串 ---------- */
    printf("\n[1] Fixed-length output\n");
    {
        const char *cases[] = { "", "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };
        int k;
        for (k = 0; k < 3; k++) {
            unsigned char hh[HASH_LEN];
            size_t hl = 0;
            if (!evp_sha256_hash((const unsigned char *)cases[k], strlen(cases[k]), hh, &hl)) {
                printf("    [ERROR] hash failed\n"); return 1;
            }
            printf("    input %d byte  ->  digest %d byte : ", (int)strlen(cases[k]), (int)hl);
            for (i = 0; i < (int)hl; i++) printf("%02x", hh[i]);
            printf("\n");
        }
    }

    /* ---------- 2. 文件 1.txt 的摘要 ---------- */
    printf("\n[2] SHA-256 of file 1.txt (streaming, 4 KB per chunk)\n");
    if (!sha256_file("1.txt", h1, &hlen, &fsize)) {
        printf("    [ERROR] cannot hash 1.txt\n"); return 1;
    }
    printf("    file size = %ld bytes\n", fsize);
    printf("    digest(%d) : ", (int)hlen);
    for (i = 0; i < (int)hlen; i++) printf("%02x", h1[i]);
    printf("\n");
    print_digest_upper("    UPPER     : ", h1, hlen);

    /* ---------- 3. 与文件内容对照 ---------- */
    printf("\n[3] File content\n");
    printf("    ------------------------------------------------------------\n");
    fp = fopen("1.txt", "rb");
    if (fp) { while ((n = (long)fread(&h2[0], 1, 1, fp)) > 0) putchar(h2[0]); fclose(fp); }
    printf("    ------------------------------------------------------------\n");

    /* ---------- 4. 篡改 1 个比特 ---------- */
    printf("\n[4] Tamper detection : flip the lowest bit of the last byte\n");
    fp = fopen("1.txt", "rb");
    if (!fp) return 1;
    data = (unsigned char *)malloc((size_t)fsize);
    n = (long)fread(data, 1, (size_t)fsize, fp);
    fclose(fp);
    printf("    original last byte = 0x%02X ('%c')\n", data[n - 1], printable(data[n - 1]));
    data[n - 1] ^= 0x01;
    printf("    tampered last byte = 0x%02X ('%c')\n", data[n - 1], printable(data[n - 1]));

    if (!evp_sha256_hash(data, (size_t)n, h2, &hlen2)) {
        printf("    [ERROR] hash failed\n"); return 1;
    }
    print_digest("\n    digest #1 (original) : ", h1, hlen);
    print_digest("    digest #2 (tampered) : ", h2, hlen2);
    printf("\n    length  : %d -> %d bytes   (unchanged)\n", (int)hlen, (int)hlen2);
    printf("    bits    : 256 bit, %d bit different (%.1f%%)\n",
           bit_difference(h1, h2, hlen), 100.0 * bit_difference(h1, h2, hlen) / 256.0);

    /* 保存被篡改文件，便于命令行 openssl dgst 复核 */
    fp = fopen("1.txt.tampered", "wb");
    if (fp) { fwrite(data, 1, (size_t)n, fp); fclose(fp); }

    /* ---------- 5. 中文/长文本示范 ---------- */
    printf("\n[5] One more sample : UTF-8 string\n");
    {
        const char *msg = "\xe5\xaf\x86\xe7\xa0\x81\xe5\xad\xa6\xe5\xae\x9e\xe9\xaa\x8c"; /* 密码学实验 */
        unsigned char hh[HASH_LEN];
        size_t hl = 0;
        evp_sha256_hash((const unsigned char *)msg, strlen(msg), hh, &hl);
        printf("    input = \"密码学实验\" (%d byte in UTF-8)\n", (int)strlen(msg));
        print_digest("    digest : ", hh, hl);
    }

    printf("\n==================================================================\n");
    printf("  All tasks finished.\n");
    printf("==================================================================\n");
    free(data);
    return 0;
}
