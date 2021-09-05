all: http_get https_get https_get_mbedtls https_post https_post_json

prebuild:
	mkdir -p build

http_get: prebuild
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

https_get: prebuild get_pem
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

https_get_mbedtls: prebuild get_pem
	gcc -static \
		-I. \
		-IcoreHTTP/source/include \
		-IcoreHTTP/source/interface \
		-IcoreHTTP/source/dependency/3rdparty/http_parser \
		-Ilogging-stack \
		-Iplatform/posix/transport/include \
		-IcorePKCS11/source/dependency/3rdparty/pkcs11 \
		-IcorePKCS11/source/include \
		-Imbedtls/include \
		-o build/https_get_mbedtls.o \
		https_get_mbedtls.c \
		coreHTTP/source/core_http_client.c \
		coreHTTP/source/dependency/3rdparty/http_parser/http_parser.c \
		corePKCS11/source/portable/mbedtls/core_pkcs11_mbedtls.c \
		corePKCS11/source/core_pkcs11.c \
		corePKCS11/source/core_pki_utils.c \
		platform/posix/transport/src/mbedtls_pkcs11_posix.c \
		-Lmbedtls/library \
		-lmbedcrypto -lmbedx509 -lmbedtls

https_post: prebuild get_pem
	gcc \
		-I. \
		-IcoreHTTP/source/include \
		-IcoreHTTP/source/interface \
		-IcoreHTTP/source/dependency/3rdparty/http_parser \
		-Ilogging-stack \
		-Iplatform/posix/transport/include \
		-o build/https_post.o \
		https_post.c \
		coreHTTP/source/core_http_client.c \
		coreHTTP/source/dependency/3rdparty/http_parser/http_parser.c \
		platform/posix/transport/src/openssl_posix.c \
		platform/posix/transport/src/sockets_posix.c \
		-lssl -lcrypto

https_post_json: prebuild get_pem
	gcc \
		-I. \
		-IcoreHTTP/source/include \
		-IcoreHTTP/source/interface \
		-IcoreHTTP/source/dependency/3rdparty/http_parser \
		-IcoreJSON/source/include \
		-Ilogging-stack \
		-Iplatform/posix/transport/include \
		-o build/https_post_json.o \
		https_post_json.c \
		coreHTTP/source/core_http_client.c \
		coreHTTP/source/dependency/3rdparty/http_parser/http_parser.c \
		coreJSON/source/core_json.c \
		platform/posix/transport/src/openssl_posix.c \
		platform/posix/transport/src/sockets_posix.c \
		-lssl -lcrypto

run: run_https_get

run_http_get: http_get
	./build/http_get.o

run_https_get: https_get
	./build/https_get.o

run_https_get_mbedtls: https_get_mbedtls
	./build/https_get_mbedtls.o

run_https_post: https_post
	./build/https_post.o

run_https_post_json: https_post_json
	./build/https_post_json.o

clean:
	rm -rf ./build

.PHONY: all prebuild http_get https_get https_get_mbedtls https_post run run_http_get run_https_get run_https_get_mbedtls run_https_post clean
