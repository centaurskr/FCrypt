/*
 * libmfcrypt - mfcrypt.h 공개 API 구현
 *
 * 파일 포맷 (모든 정수는 little-endian)
 * ------------------------------------
 *
 *   offset  0  magic[4]            = "MFCR"
 *   offset  4  version_major[1]
 *   offset  5  version_minor[1]
 *   offset  6  kdf_iterations[4]
 *   offset 10  salt[16]
 *   offset 26  nonce[12]
 *   offset 38  ciphertext[plain_len]
 *   offset 38+plain_len  tag[16]
 *
 * Key는 PBKDF2-HMAC-SHA256(password, salt, kdf_iterations)로 매 호출마다
 * 새로 유도하며, 파일 어디에도 저장되지 않는다.
 */

#include "mfcrypt.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define MFCRYPT_SALT_SIZE          16
#define MFCRYPT_KDF_ITERATIONS      200000u
#define MFCRYPT_KDF_ITERATIONS_MAX 10000000u

#define MFCRYPT_HEADER_SIZE \
    (4 + 1 + 1 + 4 + MFCRYPT_SALT_SIZE + MFCRYPT_NONCE_SIZE)

static void write_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t read_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static int validate_password(const char *password)
{
    size_t len = strlen(password);
    return (len == 0 || len > MFCRYPT_PASSWORD_MAX)
        ? MFCRYPT_ERR_PASSWORD : MFCRYPT_OK;
}

static int derive_key(
    const char *password,
    const uint8_t *salt,
    uint32_t iterations,
    uint8_t key_out[MFCRYPT_KEY_SIZE]
)
{
    int ok = PKCS5_PBKDF2_HMAC(
        password, (int)strlen(password),
        salt, MFCRYPT_SALT_SIZE,
        (int)iterations,
        EVP_sha256(),
        MFCRYPT_KEY_SIZE, key_out
    );

    return (ok == 1) ? 0 : -1;
}

int mfcrypt_encrypt(
    const uint8_t *plain,
    size_t          plain_len,
    const char     *password,
    uint8_t       **encrypted,
    size_t         *encrypted_len
)
{
    if ((plain == NULL && plain_len > 0) ||
        password == NULL ||
        encrypted == NULL ||
        encrypted_len == NULL) {
        return MFCRYPT_ERR_INVALID_PARAM;
    }

    int pw_ret = validate_password(password);
    if (pw_ret != MFCRYPT_OK) {
        return pw_ret;
    }

    /* OpenSSL EVP_*Update()는 길이를 int로 받으므로, 헤더/태그를 더한
     * 전체 크기가 INT_MAX를 넘으면 (int) 캐스트에서 값이 랩어라운드되어
     * 잘못된 길이가 전달될 수 있다. 여기서 미리 거부한다. */
    if (plain_len > (size_t)INT_MAX - MFCRYPT_HEADER_SIZE - MFCRYPT_TAG_SIZE) {
        return MFCRYPT_ERR_INVALID_PARAM;
    }

    uint8_t salt[MFCRYPT_SALT_SIZE];
    uint8_t nonce[MFCRYPT_NONCE_SIZE];

    if (RAND_bytes(salt, sizeof(salt)) != 1 ||
        RAND_bytes(nonce, sizeof(nonce)) != 1) {
        return MFCRYPT_ERR_INTERNAL;
    }

    uint8_t key[MFCRYPT_KEY_SIZE];
    if (derive_key(password, salt, MFCRYPT_KDF_ITERATIONS, key) != 0) {
        return MFCRYPT_ERR_KEY;
    }

    size_t total_len = MFCRYPT_HEADER_SIZE + plain_len + MFCRYPT_TAG_SIZE;
    uint8_t *buf = malloc(total_len);
    if (buf == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        return MFCRYPT_ERR_MEMORY;
    }

    buf[0] = 'M';
    buf[1] = 'F';
    buf[2] = 'C';
    buf[3] = 'R';
    buf[4] = (uint8_t)MFCRYPT_VERSION_MAJOR;
    buf[5] = (uint8_t)MFCRYPT_VERSION_MINOR;
    write_u32_le(buf + 6, MFCRYPT_KDF_ITERATIONS);
    memcpy(buf + 10, salt, MFCRYPT_SALT_SIZE);
    memcpy(buf + 10 + MFCRYPT_SALT_SIZE, nonce, MFCRYPT_NONCE_SIZE);

    uint8_t *ciphertext = buf + MFCRYPT_HEADER_SIZE;
    uint8_t *tag = buf + MFCRYPT_HEADER_SIZE + plain_len;

    int ret = MFCRYPT_OK;
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        ret = MFCRYPT_ERR_INTERNAL;
        goto out;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MFCRYPT_NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        ret = MFCRYPT_ERR_ENCRYPT;
        goto out;
    }

    if (plain_len > 0 &&
        EVP_EncryptUpdate(ctx, ciphertext, &out_len, plain, (int)plain_len) != 1) {
        ret = MFCRYPT_ERR_ENCRYPT;
        goto out;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &final_len) != 1) {
        ret = MFCRYPT_ERR_ENCRYPT;
        goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MFCRYPT_TAG_SIZE, tag) != 1) {
        ret = MFCRYPT_ERR_ENCRYPT;
        goto out;
    }

out:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));

    if (ret != MFCRYPT_OK) {
        OPENSSL_cleanse(buf, total_len);
        free(buf);
        return ret;
    }

    *encrypted = buf;
    *encrypted_len = total_len;
    return MFCRYPT_OK;
}

int mfcrypt_decrypt(
    const uint8_t *encrypted,
    size_t          encrypted_len,
    const char     *password,
    uint8_t       **plain,
    size_t         *plain_len
)
{
    if (encrypted == NULL ||
        password == NULL ||
        plain == NULL ||
        plain_len == NULL) {
        return MFCRYPT_ERR_INVALID_PARAM;
    }

    int pw_ret = validate_password(password);
    if (pw_ret != MFCRYPT_OK) {
        return pw_ret;
    }

    if (encrypted_len < MFCRYPT_HEADER_SIZE + MFCRYPT_TAG_SIZE) {
        return MFCRYPT_ERR_FORMAT;
    }

    const uint8_t *p = encrypted;
    if (p[0] != 'M' || p[1] != 'F' || p[2] != 'C' || p[3] != 'R') {
        return MFCRYPT_ERR_FORMAT;
    }

    /* minor 버전은 현재 헤더 레이아웃이 그대로 유지되는 한 하위 호환이지만,
     * 우리보다 높은(미래) minor는 알 수 없는 레이아웃/필드를 가정할 수 있으므로
     * 거부한다. */
    if (p[4] != (uint8_t)MFCRYPT_VERSION_MAJOR ||
        p[5] > (uint8_t)MFCRYPT_VERSION_MINOR) {
        return MFCRYPT_ERR_VERSION;
    }

    uint32_t iterations = read_u32_le(p + 6);
    if (iterations == 0 || iterations > MFCRYPT_KDF_ITERATIONS_MAX) {
        /* 조작되었거나 손상된 헤더 - CPU 소모 공격 방지 */
        return MFCRYPT_ERR_FORMAT;
    }

    const uint8_t *salt = p + 10;
    const uint8_t *nonce = p + 10 + MFCRYPT_SALT_SIZE;

    size_t ciphertext_len = encrypted_len - MFCRYPT_HEADER_SIZE - MFCRYPT_TAG_SIZE;
    const uint8_t *ciphertext = p + MFCRYPT_HEADER_SIZE;
    const uint8_t *tag = p + MFCRYPT_HEADER_SIZE + ciphertext_len;

    /* EVP_DecryptUpdate()는 길이를 int로 받으므로, (int) 캐스트에서
     * 랩어라운드가 나지 않도록 미리 거부한다. */
    if (ciphertext_len > (size_t)INT_MAX) {
        return MFCRYPT_ERR_FORMAT;
    }

    uint8_t key[MFCRYPT_KEY_SIZE];
    if (derive_key(password, salt, iterations, key) != 0) {
        return MFCRYPT_ERR_KEY;
    }

    /* ciphertext_len이 0이어도 EVP_DecryptFinal_ex에 넘길 유효한 포인터가
     * 필요하므로 최소 1바이트는 할당한다. */
    uint8_t *out_buf = malloc(ciphertext_len > 0 ? ciphertext_len : 1);
    if (out_buf == NULL) {
        OPENSSL_cleanse(key, sizeof(key));
        return MFCRYPT_ERR_MEMORY;
    }

    int ret = MFCRYPT_OK;
    int out_len = 0;
    int final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL) {
        ret = MFCRYPT_ERR_INTERNAL;
        goto out;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MFCRYPT_NONCE_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        ret = MFCRYPT_ERR_DECRYPT;
        goto out;
    }

    if (ciphertext_len > 0 &&
        EVP_DecryptUpdate(ctx, out_buf, &out_len, ciphertext, (int)ciphertext_len) != 1) {
        ret = MFCRYPT_ERR_DECRYPT;
        goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MFCRYPT_TAG_SIZE, (void *)tag) != 1) {
        ret = MFCRYPT_ERR_DECRYPT;
        goto out;
    }

    if (EVP_DecryptFinal_ex(ctx, out_buf + out_len, &final_len) <= 0) {
        /* 인증 태그 불일치: Password 오류 또는 파일 변조 */
        ret = MFCRYPT_ERR_AUTH;
        goto out;
    }

out:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(key, sizeof(key));

    if (ret != MFCRYPT_OK) {
        OPENSSL_cleanse(out_buf, ciphertext_len > 0 ? ciphertext_len : 1);
        free(out_buf);
        return ret;
    }

    *plain = out_buf;
    *plain_len = ciphertext_len;
    return MFCRYPT_OK;
}

void mfcrypt_free(void *ptr)
{
    free(ptr);
}
