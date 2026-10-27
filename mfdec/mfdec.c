/*
 * mfdec - libmfcrypt를 이용해 파일을 복호화하는 CLI 프로그램
 *
 * 사용법: mfdec <입력파일> <출력파일>
 */

/* fileno()/fsync() 등 POSIX 선언을 -std=c11(엄격 ISO C) 하에서도 노출시킨다. */
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "mfcrypt.h"

static int read_file(const char *path, uint8_t **out_buf, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        return -1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);

    uint8_t *buf = NULL;
    if (size > 0) {
        buf = malloc((size_t)size);
        if (buf == NULL) {
            fclose(fp);
            return -1;
        }
        if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
            free(buf);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    *out_buf = buf;
    *out_len = (size_t)size;
    return 0;
}

/*
 * out_path에 직접 쓰지 않고 out_path.tmp에 쓴 뒤 fsync()로 디스크 반영을
 * 보장하고 rename()으로 원자적으로 교체한다. 실패 시 임시 파일을 지워
 * 부분적으로 쓰인(특히 평문이 담긴) 파일이 남지 않게 한다.
 */
static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    size_t path_len = strlen(path);
    char *tmp_path = malloc(path_len + 5); /* ".tmp" + '\0' */
    if (tmp_path == NULL) {
        return -1;
    }
    memcpy(tmp_path, path, path_len);
    memcpy(tmp_path + path_len, ".tmp", 5);

    FILE *fp = fopen(tmp_path, "wb");
    if (fp == NULL) {
        free(tmp_path);
        return -1;
    }

    int ret = 0;
    if (len > 0 && fwrite(buf, 1, len, fp) != len) {
        ret = -1;
    }
    if (ret == 0 && (fflush(fp) != 0 || fsync(fileno(fp)) != 0)) {
        ret = -1;
    }
    if (fclose(fp) != 0) {
        ret = -1;
    }

    if (ret != 0 || rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        free(tmp_path);
        return -1;
    }

    free(tmp_path);
    return 0;
}

/*
 * 터미널 echo를 끄고 password를 입력받는다. 성공 시 0, 실패/빈 입력 시 -1.
 *
 * stdin이 tty가 아닌 경우(파이프/리다이렉션을 통한 스크립트 실행)에는
 * echo를 끌 수 없으므로 그대로 fgets()만 수행한다.
 */
static int read_password(const char *prompt, char *buf, size_t buf_size)
{
    int is_tty = isatty(STDIN_FILENO);
    struct termios old_term, new_term;

    if (is_tty) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
            return -1;
        }
        new_term = old_term;
        new_term.c_lflag &= ~ECHO;
    }

    fputs(prompt, stdout);
    fflush(stdout);

    if (is_tty && tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term) != 0) {
        return -1;
    }

    int ret = 0;
    if (fgets(buf, (int)buf_size, stdin) == NULL) {
        ret = -1;
    }

    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
    }
    fputc('\n', stdout);

    if (ret == 0) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        } else if (len == buf_size - 1) {
            /*
             * 줄바꿈 없이 버퍼가 가득 찼다 - 입력 길이가 버퍼 크기와
             * 정확히 같은 정상 케이스와 버퍼보다 긴 초과 케이스를
             * 구분하기 위해 한 글자를 더 확인한다. 초과라면 남은 입력을
             * 모두 버려서 다음 read_password() 호출로 새어 들어가지
             * 않게 한다.
             */
            int c = getchar();
            if (c != '\n' && c != EOF) {
                while (c != '\n' && c != EOF) {
                    c = getchar();
                }
                ret = -1;
            }
        }
        if (ret == 0 && buf[0] == '\0') {
            ret = -1;
        }
    }

    return ret;
}

static const char *err_str(int code)
{
    switch (code) {
    case MFCRYPT_OK:                 return "성공";
    case MFCRYPT_ERR_INVALID_PARAM:  return "잘못된 인자";
    case MFCRYPT_ERR_MEMORY:         return "메모리 할당 실패";
    case MFCRYPT_ERR_PASSWORD:       return "비밀번호 오류 (비어있거나 너무 김)";
    case MFCRYPT_ERR_FORMAT:         return "libmfcrypt 형식이 아닙니다";
    case MFCRYPT_ERR_VERSION:        return "지원하지 않는 버전";
    case MFCRYPT_ERR_ENCRYPT:        return "암호화 실패";
    case MFCRYPT_ERR_DECRYPT:        return "복호화 실패";
    case MFCRYPT_ERR_AUTH:           return "인증 실패 (비밀번호가 틀렸거나 파일이 변조되었습니다)";
    case MFCRYPT_ERR_KEY:            return "키 생성 실패";
    case MFCRYPT_ERR_INTERNAL:       return "내부 오류";
    default:                         return "알 수 없는 오류";
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "사용법: %s <입력파일> <출력파일>\n", argv[0]);
        return 1;
    }

    const char *in_path = argv[1];
    const char *out_path = argv[2];

    uint8_t *encrypted = NULL;
    size_t encrypted_len = 0;

    if (read_file(in_path, &encrypted, &encrypted_len) != 0) {
        fprintf(stderr, "입력 파일을 읽을 수 없습니다: %s\n", in_path);
        return 1;
    }

    char password[MFCRYPT_PASSWORD_MAX + 1];

    if (read_password("복호화 비밀번호: ", password, sizeof(password)) != 0) {
        fprintf(stderr, "비밀번호 입력 실패\n");
        free(encrypted);
        return 1;
    }

    uint8_t *plain = NULL;
    size_t plain_len = 0;

    int ret = mfcrypt_decrypt(encrypted, encrypted_len, password, &plain, &plain_len);

    OPENSSL_cleanse(password, sizeof(password));
    free(encrypted);

    if (ret != MFCRYPT_OK) {
        fprintf(stderr, "복호화 실패: %s\n", err_str(ret));
        return 1;
    }

    if (write_file(out_path, plain, plain_len) != 0) {
        fprintf(stderr, "출력 파일을 쓸 수 없습니다: %s\n", out_path);
        if (plain_len > 0) {
            OPENSSL_cleanse(plain, plain_len);
        }
        mfcrypt_free(plain);
        return 1;
    }

    if (plain_len > 0) {
        OPENSSL_cleanse(plain, plain_len);
    }
    mfcrypt_free(plain);

    printf("복호화 완료: %s -> %s\n", in_path, out_path);
    return 0;
}
