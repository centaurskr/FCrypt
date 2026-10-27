/*
 * ============================================================================
 *  libmfcrypt - File Encryption Library
 * ============================================================================
 *
 *  파일명 : mfcrypt.h
 *
 *  목적
 *  ----
 *  민감정보가 포함된 파일을 안전하게 암호화/복호화하기 위한
 *  libmfcrypt의 공개 API를 정의한다.
 *
 *  기본 구조
 *
 *      Application
 *          |
 *          +-- mfcrypt_encrypt()
 *          |
 *          +-- mfcrypt_decrypt()
 *          |
 *          +-- mfcrypt_free()
 *          |
 *      libmfcrypt
 *          |
 *          +-- Key Derivation
 *          +-- AES-256-GCM
 *          +-- File Format
 *
 *
 *  설계 원칙
 *  ----------
 *  1. 암호 알고리즘 자체를 직접 구현하지 않는다.
 *
 *     AES와 같은 검증된 암호 알고리즘은 직접 구현하면 안 된다.
 *     실제 암호화 처리는 OpenSSL EVP API와 같은 검증된 암호 라이브러리를
 *     사용한다.
 *
 *
 *  2. 암호화와 복호화 API를 단순하게 유지한다.
 *
 *     호출하는 프로그램에서는 암호화 내부 구조를 알 필요가 없다.
 *
 *
 *  3. 암호화 데이터와 평문 데이터를 구분한다.
 *
 *     libmfcrypt에서 생성하는 데이터에는 자체 Header를 포함시켜
 *     일반적인 파일과 구분할 수 있도록 한다.
 *
 *
 *  4. 인증 가능한 암호화를 사용한다.
 *
 *     단순 XOR 또는 단순 AES-CBC 방식이 아니라
 *     AES-256-GCM을 사용하는 것을 기본 방향으로 한다.
 *
 *     GCM은 다음 두 가지 기능을 동시에 제공한다.
 *
 *       - Confidentiality : 내용 보호
 *       - Integrity       : 데이터 변조 검출
 *
 *
 *  5. 암호화 Key를 호출 프로그램에 직접 노출하지 않는다.
 *
 *     호출자는 Password를 전달하고,
 *     실제 암호화 Key 생성 및 사용은 libmfcrypt가 담당한다.
 *
 *
 *  메모리 관리
 *  -----------
 *
 *  encrypt/decrypt 함수에서 생성되는 출력 버퍼는
 *  libmfcrypt 내부에서 동적으로 할당한다.
 *
 *  따라서 호출자는 반드시 mfcrypt_free()를 사용하여
 *  반환된 버퍼를 해제해야 한다.
 *
 *
 *  예:
 *
 *      uint8_t *encrypted = NULL;
 *      size_t encrypted_len = 0;
 *
 *      ret = mfcrypt_encrypt(
 *          plain,
 *          plain_len,
 *          password,
 *          &encrypted,
 *          &encrypted_len
 *      );
 *
 *      if (ret != MFCRYPT_OK) {
 *          ...
 *      }
 *
 *      ...
 *
 *      mfcrypt_free(encrypted);
 *
 *
 *  주의
 *  ----
 *  이 라이브러리는 "암호화 파일을 사람이 직접 열어 내용을 확인하지
 *  못하도록 하는 것"을 기본 목적으로 한다.
 *
 *  운영 환경에서 민감정보를 보호하는 경우에는 다음 사항도 중요하다.
 *
 *      - Password 관리
 *      - 실행파일 및 라이브러리 접근권한
 *      - 암호화 파일 접근권한
 *      - 복호화 후 생성되는 평문 파일의 삭제
 *      - 로그에 Password 또는 평문 데이터가 남지 않도록 하는 것
 *
 *  ============================================================================
 */

#ifndef MFCRYPT_H
#define MFCRYPT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>


/*
 * ============================================================================
 * Version
 * ============================================================================
 *
 * MFCRYPT_VERSION_MAJOR
 * MFCRYPT_VERSION_MINOR
 *
 * 라이브러리 API 또는 암호화 데이터 포맷이 변경될 경우
 * 버전을 증가시켜 호환성 문제를 관리한다.
 */

#define MFCRYPT_VERSION_MAJOR    1
#define MFCRYPT_VERSION_MINOR    0


/*
 * ============================================================================
 * Return Codes
 * ============================================================================
 *
 * 모든 public API는 아래의 결과값 중 하나를 반환한다.
 *
 *  0 이상의 값
 *      정상 처리
 *
 *  음수
 *      오류
 *
 * 오류 코드를 명확하게 정의해 두면
 * mfenc/mfdec뿐 아니라 향후 다른 프로그램에서도
 * 동일한 방식으로 오류를 처리할 수 있다.
 */

#define MFCRYPT_OK                    0

#define MFCRYPT_ERR_INVALID_PARAM    -1
#define MFCRYPT_ERR_MEMORY           -2
#define MFCRYPT_ERR_PASSWORD         -3
#define MFCRYPT_ERR_FORMAT           -4
#define MFCRYPT_ERR_VERSION          -5
#define MFCRYPT_ERR_ENCRYPT          -6
#define MFCRYPT_ERR_DECRYPT          -7
#define MFCRYPT_ERR_AUTH             -8
#define MFCRYPT_ERR_KEY              -9
#define MFCRYPT_ERR_INTERNAL        -10


/*
 * ============================================================================
 * Constants
 * ============================================================================
 */

/*
 * AES-256의 Key 길이
 *
 * AES-256은 256 bit = 32 byte Key를 사용한다.
 */
#define MFCRYPT_KEY_SIZE             32


/*
 * AES-GCM에서 사용할 Nonce 길이.
 *
 * 일반적으로 12 byte Nonce를 사용하는 것이 표준적인 선택이다.
 */
#define MFCRYPT_NONCE_SIZE           12


/*
 * GCM Authentication Tag 길이.
 *
 * 16 byte = 128 bit Authentication Tag를 사용한다.
 */
#define MFCRYPT_TAG_SIZE             16


/*
 * Password의 최대 길이.
 *
 * 이 값은 실제 암호화 Key 길이가 아니다.
 *
 * Password를 직접 AES Key로 사용하지 않고
 * 별도의 KDF(Key Derivation Function)를 이용하여
 * 32 byte Key를 생성한다.
 */
#define MFCRYPT_PASSWORD_MAX         1024


/*
 * ============================================================================
 * Public API
 * ============================================================================
 */


/*
 * --------------------------------------------------------------------------
 * mfcrypt_encrypt()
 * --------------------------------------------------------------------------
 *
 * 메모리에 존재하는 평문 데이터를 암호화한다.
 *
 *
 * 입력
 * ----
 *
 * plain
 *      암호화할 평문 데이터의 주소.
 *
 * plain_len
 *      평문 데이터의 크기(byte).
 *
 * password
 *      암호화에 사용할 Password.
 *
 *
 * 출력
 * ----
 *
 * encrypted
 *      libmfcrypt가 할당한 암호화 데이터 버퍼의 주소.
 *
 * encrypted_len
 *      암호화 데이터의 전체 크기.
 *
 *
 * 암호화 데이터에는 단순 Ciphertext만 들어가는 것이 아니다.
 *
 * 향후 다음과 같은 정보가 포함될 수 있다.
 *
 *      Header
 *      Version
 *      Nonce
 *      Ciphertext
 *      Authentication Tag
 *
 *
 * 메모리 관리
 * -----------
 *
 * encrypted는 내부에서 malloc() 등을 이용하여 생성된다.
 *
 * 호출자는 사용이 끝난 후 반드시:
 *
 *      mfcrypt_free(encrypted);
 *
 * 를 호출해야 한다.
 *
 *
 * 반환값
 * ------
 *
 * MFCRYPT_OK
 *      정상 처리
 *
 * MFCRYPT_ERR_INVALID_PARAM
 *      잘못된 인자
 *
 * MFCRYPT_ERR_MEMORY
 *      메모리 할당 실패
 *
 * MFCRYPT_ERR_PASSWORD
 *      Password 오류
 *
 * MFCRYPT_ERR_ENCRYPT
 *      암호화 처리 실패
 */
int mfcrypt_encrypt(
    const uint8_t *plain,
    size_t          plain_len,
    const char     *password,
    uint8_t       **encrypted,
    size_t         *encrypted_len
);


/*
 * --------------------------------------------------------------------------
 * mfcrypt_decrypt()
 * --------------------------------------------------------------------------
 *
 * libmfcrypt 형식으로 암호화된 데이터를 복호화한다.
 *
 *
 * 입력
 * ----
 *
 * encrypted
 *      암호화된 데이터.
 *
 * encrypted_len
 *      암호화 데이터의 전체 크기.
 *
 * password
 *      복호화에 사용할 Password.
 *
 *
 * 출력
 * ----
 *
 * plain
 *      복호화된 평문 데이터.
 *
 * plain_len
 *      평문 데이터의 크기.
 *
 *
 * 중요한 점
 * -----------
 *
 * 암호화 데이터가 변조되었거나 Password가 틀린 경우
 * 정상적인 평문을 반환해서는 안 된다.
 *
 * AES-GCM Authentication Tag 검증에 실패하면
 *
 *      MFCRYPT_ERR_AUTH
 *
 * 를 반환한다.
 *
 *
 * 반환값
 * ------
 *
 * MFCRYPT_OK
 *      정상 처리
 *
 * MFCRYPT_ERR_INVALID_PARAM
 *      잘못된 인자
 *
 * MFCRYPT_ERR_FORMAT
 *      libmfcrypt 형식이 아님
 *
 * MFCRYPT_ERR_VERSION
 *      지원하지 않는 파일 버전
 *
 * MFCRYPT_ERR_PASSWORD
 *      Password 오류
 *
 * MFCRYPT_ERR_AUTH
 *      Authentication Tag 검증 실패
 *
 * MFCRYPT_ERR_DECRYPT
 *      복호화 실패
 */
int mfcrypt_decrypt(
    const uint8_t *encrypted,
    size_t          encrypted_len,
    const char     *password,
    uint8_t       **plain,
    size_t         *plain_len
);


/*
 * --------------------------------------------------------------------------
 * mfcrypt_free()
 * --------------------------------------------------------------------------
 *
 * libmfcrypt API에서 반환된 메모리를 해제한다.
 *
 * malloc/free 구현이 서로 다른 환경에서 발생할 수 있는
 * 메모리 관리 문제를 방지하기 위해 public API에서
 * 별도의 free 함수를 제공한다.
 *
 * 예:
 *
 *      uint8_t *plain = NULL;
 *
 *      mfcrypt_decrypt(..., &plain, ...);
 *
 *      mfcrypt_free(plain);
 */
void mfcrypt_free(void *ptr);


#ifdef __cplusplus
}
#endif

#endif /* MFCRYPT_H */
