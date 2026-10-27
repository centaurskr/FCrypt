# fcrypt / libmfcrypt

민감정보가 포함된 파일을 암호화/복호화하기 위한 라이브러리(`libmfcrypt`)와
CLI 프로그램(`mfenc`, `mfdec`)이다.

- 알고리즘: AES-256-GCM (OpenSSL EVP API 사용)
- Key 유도: PBKDF2-HMAC-SHA256 (password로부터 매번 새로 유도, 파일에 Key 자체는 저장하지 않음)
- 인증: GCM Authentication Tag로 변조 여부 검증. 비밀번호가 틀리거나 파일이
  변조된 경우 평문을 반환하지 않고 오류를 반환한다.

## 디렉토리 구조

```
fcrypt/
├── include/
│   └── mfcrypt.h        # 공개 API 헤더
├── libmfcrypt/
│   └── mfcrypt.c         # 라이브러리 구현
├── mfenc/
│   └── mfenc.c           # 암호화 CLI
├── mfdec/
│   └── mfdec.c           # 복호화 CLI
└── Makefile
```

`libmfcrypt/`, `mfenc/`, `mfdec/`에는 소스 파일(`.c`/`.h`)만 두며, `.o`나
실행파일은 절대 이 안에 생성하지 않는다. 대신 이 저장소(`~/Project/fcrypt`)를
기준으로 한 상대경로로 저장소 바깥에 직접 만들어진다.

- 실행프로그램(`mfenc`, `mfdec`) → `../../bin` = `~/bin`
- 라이브러리(`libmfcrypt.a`, 중간 `.o`) → `../lib` = `~/Project/lib`

## 빌드

OpenSSL 개발 패키지(`libcrypto`, `evp.h`)가 필요하다. Makefile이 상대경로를
쓰므로 반드시 저장소 루트(`~/Project/fcrypt`)에서 `make`를 실행해야 한다.

```sh
make            # ~/Project/lib/libmfcrypt.a, ~/bin/mfenc, ~/bin/mfdec 생성
make clean      # 위에서 생성된 .o/.a/실행파일 삭제
```

별도의 `install` 단계는 없다 — `make`만으로 바로 최종 위치에 결과물이
생긴다.

## 사용법

### 파일 암호화 (mfenc)

```sh
mfenc <입력파일> <출력파일>
```

암호화 비밀번호를 두 번 입력받는다(확인용). 터미널에서 실행하면 입력한
문자는 화면에 표시되지 않는다.

```
$ mfenc secret.txt secret.mfc
암호화 비밀번호: 
비밀번호 확인: 
암호화 완료: secret.txt -> secret.mfc
```

### 파일 복호화 (mfdec)

```sh
mfdec <입력파일> <출력파일>
```

```
$ mfdec secret.mfc secret_restored.txt
복호화 비밀번호: 
복호화 완료: secret.mfc -> secret_restored.txt
```

비밀번호가 틀리거나 파일이 변조된 경우, 출력 파일을 생성하지 않고 오류
메시지를 출력한 뒤 0이 아닌 종료 코드를 반환한다.

```
$ mfdec secret.mfc out.txt
복호화 비밀번호: 
복호화 실패: 인증 실패 (비밀번호가 틀렸거나 파일이 변조되었습니다)
```

### 스크립트에서 사용하기

`mfenc`/`mfdec`는 stdin이 터미널이 아니면(파이프/리다이렉션) echo를 끄지
않고 그대로 비밀번호를 읽는다. 자동화 스크립트에서 사용할 수 있다.

```sh
printf '내비밀번호\n내비밀번호\n' | mfenc secret.txt secret.mfc
printf '내비밀번호\n' | mfdec secret.mfc secret.txt
```

## 주의사항

이 도구는 "암호화된 파일을 사람이 직접 열어 내용을 바로 확인하지 못하도록
하는 것"까지만 보장한다. 운영 환경에서 민감정보를 실제로 보호하려면 다음도
함께 관리해야 한다.

- 비밀번호 관리 (분실 시 복호화 불가능, 유출 시 무의미)
- 실행파일 및 라이브러리 접근권한
- 암호화 파일 접근권한
- 복호화 후 생성되는 평문 파일의 삭제
- 로그에 비밀번호 또는 평문 데이터가 남지 않도록 하는 것

## 라이브러리 API

CLI 대신 다른 프로그램에서 직접 `libmfcrypt`를 사용하려면
`include/mfcrypt.h`의 `mfcrypt_encrypt()` / `mfcrypt_decrypt()` /
`mfcrypt_free()`를 사용한다. 자세한 사용법과 반환값은 헤더의 주석을
참고한다.
