#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core_http_config.h"
#include "core_http_client.h"
#include "openssl_posix.h"

#define HTTPS_PORT 443
#define TRANSPORT_SEND_RECV_TIMEOUT_MS 1000
#define USER_BUFFER_LENGTH 1024

int32_t connectToServer(NetworkContext_t *pNetworkContext,
    const char *pRootCaPath,
    const char *sniHostName,
    const char *host,
    size_t hostLen,
    const unsigned int port);
HTTPResponse_t request(const TransportInterface_t *pTransportInterface,
                        const char *pMethod,
                        size_t methodLen,
                        const char *pHost,
                        size_t hostLen,
                        const char *pPath,
                        size_t pathLen,
                        const char *requestBody,
                        size_t requestBodyLen);
void https_post();

struct NetworkContext {
  OpensslParams_t *pParams;
};

uint8_t userBuffer[USER_BUFFER_LENGTH];

int32_t connectToServer(NetworkContext_t *pNetworkContext, const char *pRootCaPath, const char *sniHostName, const char *host, size_t hostLen, const unsigned int port) {
  int32_t returnStatus = EXIT_FAILURE;
  OpensslStatus_t opensslStatus;
  OpensslCredentials_t opensslCredentials = {0};
  ServerInfo_t serverInfo;

  opensslCredentials.pRootCaPath = pRootCaPath;
  opensslCredentials.sniHostName = sniHostName;

  serverInfo.pHostName = host;
  serverInfo.hostNameLength = hostLen;
  serverInfo.port = port;

  opensslStatus = Openssl_Connect(pNetworkContext, &serverInfo, &opensslCredentials, TRANSPORT_SEND_RECV_TIMEOUT_MS, TRANSPORT_SEND_RECV_TIMEOUT_MS);

  if (opensslStatus == SOCKETS_SUCCESS) {
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
                                size_t pathLen,
                                const char *requestBody,
                                size_t requestBodyLen) {
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

    httpStatus = HTTPClient_Send(pTransportInterface,
                                  &requestHeaders,
                                  requestBody,
                                  requestBodyLen,
                                  &response,
                                  0);
  } else {
    LogError(("Failed to initialize HTTP request headers: Error=%s.", HTTPClient_strerror(httpStatus)));
  }

  return response;
}

void https_post() {
  int32_t returnStatus = EXIT_SUCCESS;
  TransportInterface_t transportInterface = {0};
  NetworkContext_t networkContext;
  OpensslParams_t opensslParams;
  networkContext.pParams = &opensslParams;

  const char *pRootCaPath = "certificates/AmazonRootCA1.crt";
  const char *sniHostName = "httpbin.org";
  const char *hostname = "httpbin.org";
  const char *path = "/post";
  const char body[] = "Hello, world!";
  size_t bodyLen = sizeof(body) - 1U;

  returnStatus = connectToServer(&networkContext, pRootCaPath, sniHostName, hostname, 11, HTTPS_PORT);

  transportInterface.recv = Openssl_Recv;
  transportInterface.send = Openssl_Send;
  transportInterface.pNetworkContext = &networkContext;

  HTTPResponse_t response = request(&transportInterface, "POST", 4, hostname, 11, path, 5, body, bodyLen);

  printf("Received HTTP response from %s%s...\n"
           "Response Headers: %s\n"
           "Response Status: %u\n"
           "Response Body: %s\n",
           hostname, path,
           response.pHeaders,
           response.statusCode,
           response.pBody);

  Openssl_Disconnect(&networkContext);
}

int main(void) {
  https_post();

  return 0;
}
