all: http_get

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

run: run_http

run_http: http_get
	./build/http_get.o

clean:
	rm -rf ./clean

.PHONY: all http_get run_http clean
