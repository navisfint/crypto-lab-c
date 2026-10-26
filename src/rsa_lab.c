/* ==========================================================================
 *  实验 1-2  非对称密码算法 RSA（OpenSSL 3.x EVP 高层接口）
 *  -------------------------------------------------------------------------
 *  功能：
 *    1) 由固定种子生成个性化上下文（私钥 PEM 的保护口令 = 由种子派生），
 *       并用 EVP_PKEY_keygen 生成 2048 位 RSA 密钥对；
 *    2) 用 RSA-OAEP(SHA-256) 对文件 1.txt 分块加密、解密，逐字节比对；
 *    3) 演示 RSA 明文长度上限（256 - 2*32 - 2 = 190 字节），
 *       超长输入由 EVP 直接拒绝 —— 说明非对称算法需配合分组/混合加密；
 *    4) 反面验证：篡改 1 字节密文后解密失败。
 *  编译：cl -nologo -utf-8 -O2 -MD -Fe:rsa_lab.exe rsa_lab.c -link libcrypto.lib
 * ========================================================================== */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

/* Windows 下用动态 libcrypto 且通过 FILE* 使用 PEM 接口时必须包含 applink.c */
#include <openssl/applink.c>

#define STUDENT_ID   1000
#define RSA_BITS      2048
#define BLOCK_SIZE    (RSA_BITS / 8)     /* 256 字节 */

static void print_hex(const char *label, const unsigned char *buf, int len)
{
    int i;
    printf("%s", label);
    for (i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len) printf("\n%*s", (int)strlen(label), "");
    }
    printf("\n");
}

static int read_file(const char *path, unsigned char **out, int *out_len)
{
    FILE *fp = fopen(path, "rb");
    long  size;
    if (!fp) return 0;
    fseek(fp, 0, SEEK_END); size = ftell(fp); fseek(fp, 0, SEEK_SET);
    *out = (unsigned char *)malloc(size ? size : 1);
    if (!*out) { fclose(fp); return 0; }
    *out_len = (int)fread(*out, 1, size, fp);
    fclose(fp);
    return 1;
}

/*--------------------------------------------------------------------------
 * 种子值 -> 私钥保护口令
 *------------------------------------------------------------------------*/
static void personalized_passphrase(char *out, size_t n)
{
    snprintf(out, n, "RSA-KEY-%d-%d", STUDENT_ID, STUDENT_ID * 7);
}

/*--------------------------------------------------------------------------
 * 生成 RSA 密钥对（EVP_PKEY_keygen）
 *------------------------------------------------------------------------*/
EVP_PKEY* evp_generate_rsa_key_pair(int student_id)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY     *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0)                       goto done;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_BITS) <= 0)  goto done;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)                      goto done;

    printf("    keygen ok, student_id = %d, modulus = %d bit\n", student_id, RSA_BITS);
done:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/*--------------------------------------------------------------------------
 * RSA 加密（RSA-OAEP + SHA-256）
 *------------------------------------------------------------------------*/
int evp_rsa_encrypt(EVP_PKEY *public_key,
                    const unsigned char *plaintext, int plaintext_len,
                    unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_PKEY_CTX *ctx;
    size_t outlen = 0;

    ctx = EVP_PKEY_CTX_new(public_key, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_encrypt_init(ctx) <= 0)                       goto fail;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)   goto fail;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)   goto fail;

    outlen = (size_t)*ciphertext_len;
    if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, (size_t)plaintext_len) <= 0)
        goto fail;
    *ciphertext_len = (int)outlen;

    EVP_PKEY_CTX_free(ctx);
    return 1;
fail:
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

/*--------------------------------------------------------------------------
 * RSA 解密；返回 1 成功、0 一般失败、-1 填充/校验失败
 *------------------------------------------------------------------------*/
int evp_rsa_decrypt(EVP_PKEY *private_key,
                    const unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *plaintext, int *plaintext_len)
{
    EVP_PKEY_CTX *ctx;
    size_t outlen = 0;

    ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) return 0;

    if (EVP_PKEY_decrypt_init(ctx) <= 0)                       goto fail;
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0)   goto fail;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)   goto fail;

    outlen = (size_t)*plaintext_len;
    if (EVP_PKEY_decrypt(ctx, plaintext, &outlen, ciphertext, (size_t)ciphertext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;                       /* 填充校验失败：密文被篡改或密钥不匹配 */
    }
    *plaintext_len = (int)outlen;

    EVP_PKEY_CTX_free(ctx);
    return 1;
fail:
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

static int pass_cb(char *buf, int size, int rwflag, void *u)
{
    const char *pass = (const char *)u;
    int n = (int)strlen(pass);
    (void)rwflag;
    if (n > size) n = size;
    memcpy(buf, pass, n);
    return n;
}

int main(void)
{
    EVP_PKEY *pkey = NULL;
    unsigned char *plain = NULL, *cipher = NULL, *back = NULL;
    int  plain_len = 0, total_c = 0, total_p = 0;
    int  i, blocks, ret, diff = 0;
    char pass[64];
    FILE *fp;
    size_t max_in;

    printf("#################################################################\n");
    printf("#  Lab 1-2  RSA-2048 with OpenSSL EVP   (STUDENT_ID = %d)\n", STUDENT_ID);
    printf("#  %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("#################################################################\n");

    /* ---------- 1. 生成密钥对 ---------- */
    printf("\n[1] Generate personalized RSA key pair\n");
    pkey = evp_generate_rsa_key_pair(STUDENT_ID);
    if (!pkey) { printf("    [ERROR] keygen failed\n"); return 1; }
    personalized_passphrase(pass, sizeof(pass));
    printf("    private-key passphrase (derived from ID) : %s\n", pass);

    /* ---------- 2. 导出 PEM ---------- */
    printf("\n[2] Export PEM files\n");
    fp = fopen("rsa_public.pem", "wb");
    if (fp) { PEM_write_PUBKEY(fp, pkey); fclose(fp); }
    fp = fopen("rsa_private.pem", "wb");
    if (fp) {
        PEM_write_PrivateKey(fp, pkey, EVP_aes_256_cbc(), NULL, 0,
                             pass_cb, pass);
        fclose(fp);
    }
    {
        long pub_sz = 0, pri_sz = 0;
        fp = fopen("rsa_public.pem", "rb");
        if (fp) { fseek(fp, 0, SEEK_END); pub_sz = ftell(fp); fclose(fp); }
        fp = fopen("rsa_private.pem", "rb");
        if (fp) { fseek(fp, 0, SEEK_END); pri_sz = ftell(fp); fclose(fp); }
        printf("    rsa_public.pem  : %ld bytes\n", pub_sz);
        printf("    rsa_private.pem : %ld bytes (encrypted by AES-256-CBC, student passphrase)\n", pri_sz);
    }

    /* ---------- 3. 明文长度上限 ---------- */
    max_in = (size_t)EVP_PKEY_size(pkey) - 2 * 32 - 2;
    printf("\n[3] RSA-OAEP(SHA-256) plaintext limit = %d - 2*32 - 2 = %d bytes\n",
           (int)EVP_PKEY_size(pkey), (int)max_in);

    /* ---------- 4. 读文件 ---------- */
    if (!read_file("1.txt", &plain, &plain_len)) {
        printf("    [ERROR] cannot open 1.txt\n"); return 1;
    }
    blocks = (plain_len + (int)max_in - 1) / (int)max_in;
    printf("    file 1.txt : %d bytes  -> %d RSA block(s)\n", plain_len, blocks);

    /* ---------- 5. 分块加密 ---------- */
    cipher = (unsigned char *)malloc(blocks * BLOCK_SIZE);
    printf("\n[4] Encrypt block by block\n");
    for (i = 0; i < blocks; i++) {
        int chunk = plain_len - i * (int)max_in;
        int clen  = BLOCK_SIZE;
        if (chunk > (int)max_in) chunk = (int)max_in;
        if (!evp_rsa_encrypt(pkey, plain + i * (int)max_in, chunk,
                             cipher + total_c, &clen)) {
            printf("    [ERROR] encrypt block %d failed\n", i + 1);
            return 1;
        }
        printf("    block %d : plain %3d byte -> cipher %3d byte\n", i + 1, chunk, clen);
        total_c += clen;
    }
    printf("    total ciphertext : %d bytes\n", total_c);
    print_hex("    HEX(first 64B) : ", cipher, total_c > 64 ? 64 : total_c);
    fp = fopen("1.txt.rsa", "wb");
    if (fp) { fwrite(cipher, 1, total_c, fp); fclose(fp); }
    printf("    saved to 1.txt.rsa\n");

    /* ---------- 6. 分块解密 ---------- */
    back = (unsigned char *)malloc(total_c + 1);
    printf("\n[5] Decrypt block by block\n");
    for (i = 0; i < blocks; i++) {
        int plen = BLOCK_SIZE;             /* 输出缓冲上限 */
        ret = evp_rsa_decrypt(pkey, cipher + i * BLOCK_SIZE, BLOCK_SIZE,
                              back + total_p, &plen);
        if (ret != 1) {
            printf("    [ERROR] decrypt block %d failed, ret = %d\n", i + 1, ret);
            return 1;
        }
        printf("    block %d : cipher %3d byte -> plain %3d byte\n", i + 1, BLOCK_SIZE, plen);
        total_p += plen;
    }
    back[total_p] = '\0';
    printf("\n[6] Decrypted text (%d bytes)\n", total_p);
    printf("    ------------------------------------------------------------\n");
    fwrite(back, 1, total_p, stdout);
    printf("\n    ------------------------------------------------------------\n");

    printf("\n[7] Integrity check (byte by byte)\n");
    if (plain_len == total_p) {
        for (i = 0; i < plain_len; i++) if (plain[i] != back[i]) diff++;
        printf("    mismatched bytes = %d  ->  %s\n", diff,
               diff == 0 ? "IDENTICAL" : "DIFFERENT");
    } else {
        printf("    length mismatch -> DIFFERENT\n");
    }

    /* ---------- 7. 超长输入被拒绝 ---------- */
    printf("\n[8] Negative test 1 : plaintext longer than the limit\n");
    {
        unsigned char big[256], tmp[512];
        int tlen = BLOCK_SIZE;
        memset(big, 'A', sizeof(big));
        if (!evp_rsa_encrypt(pkey, big, (int)max_in + 1, tmp, &tlen)) {
            unsigned long e = ERR_get_error();
            printf("    encrypt %d bytes -> FAILED : %s\n", (int)max_in + 1,
                   e ? ERR_reason_error_string(e) : "error");
        } else {
            printf("    encrypt %d bytes -> unexpected success\n", (int)max_in + 1);
        }
        ERR_clear_error();
    }

    /* ---------- 8. 篡改密文 ---------- */
    printf("\n[9] Negative test 2 : tamper 1 byte of ciphertext\n");
    cipher[10] ^= 0x80;
    {
        int plen = BLOCK_SIZE;
        ret = evp_rsa_decrypt(pkey, cipher, BLOCK_SIZE, back, &plen);
        printf("    decrypt() returned %d  ->  %s\n", ret,
               ret == -1 ? "OAEP padding check failed (tampered ciphertext)" : "unexpected");
        cipher[10] ^= 0x80;
        ERR_clear_error();
    }

    printf("\n==================================================================\n");
    printf("  All tasks finished.\n");
    printf("==================================================================\n");

    EVP_PKEY_free(pkey);
    free(plain); free(cipher); free(back);
    return 0;
}
