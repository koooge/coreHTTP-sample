#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

// coreHTTP
#include "core_http_config.h"
#include "core_http_client.h"

// mbedtls
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"

#define HTTPS_PORT 443
#define TRANSPORT_SEND_RECV_TIMEOUT_MS 1000
#define USER_BUFFER_LENGTH 1024
// #define REQUEST_BODY "Hello, world!"

int32_t connectToServer(NetworkContext_t *pNetworkContext,
    const char *pRootCaPath,
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

/** platform imitation BEGIN */
typedef struct MbedtlsContext {
  mbedtls_net_context socketContext;
  mbedtls_ssl_config config;
  mbedtls_ssl_context context;
  mbedtls_x509_crt_profile certProfile;
  mbedtls_x509_crt rootCa;
} MbedtlsContext_t;

uint32_t Mbedtls_Connect(NetworkContext_t *pNetworkContext,
                                      const char *pHostName,
                                      uint16_t port,
                                      const char *pRootCaPath,
                                      uint32_t recvTimeoutMs);
int32_t Mbedtls_Recv(NetworkContext_t *pNetworkContext,
                     void *pBuffer,
                     size_t bytesToRecv);
int32_t Mbedtls_Send(NetworkContext_t *pNetworkContext,
                            const void *pBuffer,
                            size_t bytesToSend);
void Mbedtls_Disconnect(NetworkContext_t *pNetworkContext);
void contextInit(MbedtlsContext_t *pContext);
void contextFree(MbedtlsContext_t *pContext);

struct NetworkContext {
  MbedtlsContext_t *pParams;
};

// typedef struct MbedtlsCredentials {
// } MbedtlsCredentials_t;
/** platform imitation END */

uint8_t userBuffer[USER_BUFFER_LENGTH];

int32_t connectToServer(NetworkContext_t *pNetworkContext, const char *pRootCaPath, const char *host, size_t hostLen, const unsigned int port) {
  return Mbedtls_Connect(pNetworkContext, host, port, pRootCaPath, TRANSPORT_SEND_RECV_TIMEOUT_MS);
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
  MbedtlsContext_t tlsContext = {0};
  networkContext.pParams = &tlsContext;

  const char *pRootCaPath = "certificates/AmazonRootCA1.crt";
  const char *hostname = "httpbin.org";
  const char *path = "/get";

  returnStatus = connectToServer(&networkContext, pRootCaPath, hostname, 11, HTTPS_PORT);
  if (returnStatus == EXIT_FAILURE) {
    fprintf(stderr, "https_get: connectToServer Failed. returnStatus = %d\n", returnStatus);
    return;
  }

  transportInterface.recv = Mbedtls_Recv;
  transportInterface.send = Mbedtls_Send;
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

  Mbedtls_Disconnect(&networkContext);
}

/** platform imitation BEGIN */
uint32_t Mbedtls_Connect(NetworkContext_t *pNetworkContext,
                                      const char *pHostName,
                                      uint16_t port,
                                      const char *pRootCaPath,
                                      uint32_t recvTimeoutMs) {
  // configureMbedtls() BEGIN
  int32_t mbedtlsError = 0;
  contextInit(pNetworkContext->pParams);
  mbedtlsError = mbedtls_ssl_config_defaults(&(pNetworkContext->pParams->config),
                                                MBEDTLS_SSL_IS_CLIENT,
                                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                                MBEDTLS_SSL_PRESET_DEFAULT );
  if (mbedtlsError != 0) {
    fprintf(stderr, "Mbedtls_Connect: mbedtls_ssl_config_defaults Failed. tlsStatus = %d\n", mbedtlsError);
  }

  mbedtls_ssl_conf_authmode(&(pNetworkContext->pParams->config), MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_rng(&(pNetworkContext->pParams->config), mbedtls_ctr_drbg_random, pNetworkContext->pParams);

  // configureMbedtlsCertificates() BEGIN
  mbedtls_x509_crt_parse_file(&(pNetworkContext->pParams->rootCa), pRootCaPath);
  mbedtls_ssl_conf_ca_chain(&(pNetworkContext->pParams->config), &(pNetworkContext->pParams->rootCa), NULL);
  // configureMbedtlsCertificates() END

  // configureMbedtlsSniAlpn() BEGIN
  mbedtls_ssl_set_hostname(&(pNetworkContext->pParams->context), pHostName);

  // configureMbedtlsSniAlpn() END

  mbedtls_ssl_set_bio(&(pNetworkContext->pParams->context),
                             ( void * ) &(pNetworkContext->pParams->socketContext),
                             mbedtls_net_send,
                             mbedtls_net_recv,
                             mbedtls_net_recv_timeout);
  // configureMbedtls() END

  char portStr[6] = {0};
  snprintf(portStr, sizeof(portStr), "%u", port);
  return mbedtls_net_connect(&(pNetworkContext->pParams->socketContext), pHostName, portStr, MBEDTLS_NET_PROTO_TCP);
}

int32_t Mbedtls_Recv(NetworkContext_t *pNetworkContext, void *pBuffer, size_t bytesToRecv) {
  int32_t tlsStatus = 0;
  tlsStatus = mbedtls_ssl_read(&(pNetworkContext->pParams->context), pBuffer, bytesToRecv);
  if (tlsStatus < 0) {
    fprintf(stderr, "Mbedtls_Recv: mbedtls_ssl_read Failed. tlsStatus = %d\n", tlsStatus);
  }
  return tlsStatus;
}

int32_t Mbedtls_Send(NetworkContext_t *pNetworkContext, const void *pBuffer, size_t bytesToSend) {
  int32_t tlsStatus = 0;
  tlsStatus = mbedtls_ssl_write(&(pNetworkContext->pParams->context), pBuffer, bytesToSend);
  if (tlsStatus < 0) {
    fprintf(stderr, "Mbedtls_Send: mbedtls_ssl_write Failed. tlsStatus = %d\n", tlsStatus);
  }
  return tlsStatus;
}

void Mbedtls_Disconnect(NetworkContext_t *pNetworkContext) {
  (void)mbedtls_ssl_close_notify(&(pNetworkContext->pParams->context));
  contextFree(pNetworkContext->pParams);
}

void contextInit(MbedtlsContext_t *pContext) {
    assert( pContext != NULL );

    mbedtls_net_init( &( pContext->socketContext ) );
    mbedtls_ssl_init( &( pContext->context ) );
    mbedtls_ssl_config_init( &( pContext->config ) );
    mbedtls_x509_crt_init( &( pContext->rootCa ) );
}

void contextFree(MbedtlsContext_t *pContext) {
  if (pContext != NULL) {
    mbedtls_net_free( &( pContext->socketContext ) );
    mbedtls_ssl_free( &( pContext->context ) );
    mbedtls_ssl_config_free( &( pContext->config ) );
    mbedtls_x509_crt_free( &( pContext->rootCa ) );
  }
}
/** platform imitation END */

int main(void) {
  https_get();

  return 0;
}
