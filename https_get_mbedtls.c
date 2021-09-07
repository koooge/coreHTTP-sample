#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "core_http_config.h"
#include "core_http_client.h"
#include "mbedtls_pkcs11_posix.h"

#define HTTPS_PORT 443
#define TRANSPORT_SEND_RECV_TIMEOUT_MS 1000
#define USER_BUFFER_LENGTH 1024
// #define REQUEST_BODY "Hello, world!"

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
                        size_t pathLen);
void https_get();

struct NetworkContext {
  MbedtlsPkcs11Context_t *pParams;
};

uint8_t userBuffer[USER_BUFFER_LENGTH];

int32_t connectToServer(NetworkContext_t *pNetworkContext, const char *pRootCaPath, const char *sniHostName, const char *host, size_t hostLen, const unsigned int port) {
  int32_t returnStatus = EXIT_FAILURE;
  MbedtlsPkcs11Status_t tlsStatus;
  MbedtlsPkcs11Credentials_t tlsCredentials = {0};
  CK_SESSION_HANDLE p11Session;
  // const char *alpn[] = {ALPN_PROTOCOL_NAME, NULL};

  tlsCredentials.pRootCaPath = pRootCaPath;
  tlsCredentials.pClientCertLabel = "some"; // pClientCertLabel;
  tlsCredentials.pPrivateKeyLabel = "somekey"; // pPrivateKeyLabel;
  tlsCredentials.p11Session = p11Session;
  tlsCredentials.disableSni = false;
  // tlsCredentials.pAlpnProtos = alpn;

  tlsStatus = Mbedtls_Pkcs11_Connect(pNetworkContext, host, port, &tlsCredentials, TRANSPORT_SEND_RECV_TIMEOUT_MS);

  if (tlsStatus == MBEDTLS_PKCS11_SUCCESS) {
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

void https_get() {
  int32_t returnStatus = EXIT_SUCCESS;
  TransportInterface_t transportInterface = {0};
  NetworkContext_t networkContext = {0};
  MbedtlsPkcs11Context_t tlsContext = { 0 };
  networkContext.pParams = &tlsContext;

  const char *pRootCaPath = "certificates/AmazonRootCA1.crt";
  const char *sniHostName = "httpbin.org";
  const char *hostname = "httpbin.org";
  const char *path = "/get";

  returnStatus = connectToServer(&networkContext, pRootCaPath, sniHostName, hostname, 11, HTTPS_PORT);
  if (returnStatus == EXIT_FAILURE) {
    fprintf(stderr, "https_get: connectToServer Failed. returnStatus = %d\n", returnStatus);
    return returnStatus;
  }

  transportInterface.recv = Mbedtls_Pkcs11_Recv;
  transportInterface.send = Mbedtls_Pkcs11_Send;
  transportInterface.pNetworkContext = &networkContext;

  HTTPResponse_t response = request(&transportInterface, "GET", 3, hostname, 11, path, 4);

  printf("Received HTTP response from %s%s...\n"
           "Response Headers: %s\n"
           "Response Status: %u\n"
           "Response Body: %s\n",
           hostname, path,
           response.pHeaders,
           response.statusCode,
           response.pBody);

  Mbedtls_Pkcs11_Disconnect(&networkContext);
}

int main(void) {
  https_get();

  return 0;
}
