all: http_get https_get

http_get:
	mkdir -p build
	gcc \
		-I. \
		-IcoreHTTP/source/include \
		-IcoreHTTP/source/interface \
		-IcoreHTTP/source/dependency/3rdparty/http_parser \
		-Ilogging-stack \
		-Iplatform/posix/transport/include \
		-o build/http_get.o \
		http_get.c \
		coreHTTP/source/core_http_client.c \
		coreHTTP/source/dependency/3rdparty/http_parser/http_parser.c \
		platform/posix/transport/src/plaintext_posix.c \
		platform/posix/transport/src/sockets_posix.c

get_pem:
	curl -sSL --url https://www.amazontrust.com/repository/AmazonRootCA1.pem -o certificates/AmazonRootCA1.crt

https_get: get_pem
	mkdir -p build
	gcc \
		-I. \
		-IcoreHTTP/source/include \
		-IcoreHTTP/source/interface \
		-IcoreHTTP/source/dependency/3rdparty/http_parser \
		-Ilogging-stack \
		-Iplatform/posix/transport/include \
		-o build/https_get.o \
		https_get.c \
		coreHTTP/source/core_http_client.c \
		coreHTTP/source/dependency/3rdparty/http_parser/http_parser.c \
		platform/posix/transport/src/openssl_posix.c \
		platform/posix/transport/src/sockets_posix.c \
		-lssl -lcrypto

run: run_https_get

run_http_get: http_get
	./build/http_get.o

run_https_get: https_get
	./build/https_get.o

clean:
	rm -rf ./clean

.PHONY: all http_get https_get run run_http_get run_https_get clean
