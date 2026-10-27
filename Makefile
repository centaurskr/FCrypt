CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -std=c11 -Iinclude
LDLIBS  = -lcrypto

# 산출물(.o, 라이브러리, 실행파일)은 source dir(libmfcrypt/, mfenc/, mfdec/)에
# 남기지 않는다. 실행프로그램은 ../../bin, library는 ../lib에 생성한다.
# (이 Makefile 위치인 프로젝트 루트 기준 상대경로)
BIN_DIR = ../../bin
LIB_DIR = ../lib
OBJ_DIR = $(LIB_DIR)/obj

LIB     = $(LIB_DIR)/libmfcrypt.a
LIB_OBJ = $(OBJ_DIR)/mfcrypt.o

MFENC   = $(BIN_DIR)/mfenc
MFDEC   = $(BIN_DIR)/mfdec

.PHONY: all clean

all: $(MFENC) $(MFDEC)

$(OBJ_DIR) $(LIB_DIR) $(BIN_DIR):
	mkdir -p $@

$(OBJ_DIR)/mfcrypt.o: libmfcrypt/mfcrypt.c include/mfcrypt.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(LIB_OBJ) | $(LIB_DIR)
	ar rcs $@ $^

$(MFENC): mfenc/mfenc.c $(LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ mfenc/mfenc.c $(LIB) $(LDLIBS)

$(MFDEC): mfdec/mfdec.c $(LIB) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ mfdec/mfdec.c $(LIB) $(LDLIBS)

clean:
	rm -f $(LIB_OBJ) $(LIB) $(MFENC) $(MFDEC)
	rmdir $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR) 2>/dev/null || true
