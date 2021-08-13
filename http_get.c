#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core_http_config.h"
#include "core_http_client.h"
#include "plaintext_posix.h"

#define HTTP_PORT 80
#define TRANSPORT_SEND_RECV_TIMEOUT_MS 1000
#define USER_BUFFER_LENGTH 1024
// #define REQUEST_BODY "Hello, world!"

int32_t connectToServer(NetworkContext_t *pNetworkContext, const char *host, size_t hostLen, const unsigned int port);
HTTPResponse_t request(const TransportInterface_t *pTransportInterface,
                        const char *pMethod,
                        size_t methodLen,
                        const char *pHost,
                        size_t hostLen,
                        const char *pPath,
                        size_t pathLen);
void http_get();

struct NetworkContext {
  PlaintextParams_t *pParams;
};

uint8_t userBuffer[USER_BUFFER_LENGTH];

int32_t connectToServer(NetworkContext_t *pNetworkContext, const char *host, size_t hostLen, const unsigned int port) {
  int32_t returnStatus = EXIT_FAILURE;
  SocketStatus_t socketStatus;
  ServerInfo_t serverInfo;

  serverInfo.pHostName = host;
  serverInfo.hostNameLength = hostLen;
  serverInfo.port = port;

  socketStatus = Plaintext_Connect(pNetworkContext, &serverInfo, TRANSPORT_SEND_RECV_TIMEOUT_MS, TRANSPORT_SEND_RECV_TIMEOUT_MS);

  if (socketStatus == SOCKETS_SUCCESS) {
    returnStatus = EXIT_SUCCESS;
  } else {
    returnStatus = EXIT_FAILURE;
  }

  return returnStatus;
}

HTTPResponse_t request(const TransportInterface_t *pTransportInterface,
                                const char *pMethod,
                                size_t methodLen,
                                const char *pHost,
                                size_t hostLen,
                                const char *pPath,
                                size_t pathLen) {
  HTTPStatus_t httpStatus = HTTPSuccess;
  HTTPRequestInfo_t requestInfo = {0};
  HTTPResponse_t response = {0};
  HTTPRequestHeaders_t requestHeaders = {0};

  requestInfo.pMethod = pMethod;
  requestInfo.methodLen = methodLen;
  requestInfo.pHost = pHost;
  requestInfo.hostLen = hostLen;
  requestInfo.pPath = pPath;
  requestInfo.pathLen = pathLen;
  requestInfo.reqFlags = HTTP_REQUEST_KEEP_ALIVE_FLAG;

  requestHeaders.pBuffer = userBuffer;
  requestHeaders.bufferLen = USER_BUFFER_LENGTH;

  httpStatus = HTTPClient_InitializeRequestHeaders(&requestHeaders, &requestInfo);

  if (httpStatus == HTTPSuccess) {
    response.pBuffer = userBuffer;
    response.bufferLen = USER_BUFFER_LENGTH;

    httpStatus = HTTPClient_Send( pTransportInterface,
                                  &requestHeaders,
                                  0, // ( uint8_t * ) REQUEST_BODY,
                                  0, // REQUEST_BODY_LENGTH,
                                  &response,
                                  0 );
  } else {
    LogError(("Failed to initialize HTTP request headers: Error=%s.", HTTPClient_strerror(httpStatus)));
  }

  return response;
}

void http_get() {
  int32_t returnStatus = EXIT_SUCCESS;
  TransportInterface_t transportInterface = {0};
  NetworkContext_t networkContext;
  PlaintextParams_t plaintextParams;
  networkContext.pParams = &plaintextParams;

  char *hostname = "httpbin.org";
  char *path = "/get";

  returnStatus = connectToServer(&networkContext, hostname, 11, HTTP_PORT);

  transportInterface.recv = Plaintext_Recv;
  transportInterface.send = Plaintext_Send;
  transportInterface.pNetworkContext = &networkContext;

  HTTPResponse_t response = request(&transportInterface, "GET", 3, hostname, 11, "/get", 4);
  printf("Received HTTP response from %s%s...\n"
           "Response Headers: %s\n"
           "Response Status: %u\n"
           "Response Body: %s\n",
           hostname, path,
           response.pHeaders,
           response.statusCode,
           response.pBody);

  Plaintext_Disconnect(&networkContext);
}

int main(void) {
  http_get();

  return 0;
}
