/*
 * ht_ssl.h - Per-connection TLS state (backend-specific fields)
 */

#ifndef AMIHTTP_PRIVATE_HT_SSL_H
#define AMIHTTP_PRIVATE_HT_SSL_H

#ifndef EXEC_TYPES_H
#include <exec/types.h>
#endif

#include "private/ht_ssl_config.h"

#ifdef AMIHTTP_USE_AMITLS
struct TlsContext;
struct TlsConnection;
#endif

struct HtSsl
{
#ifdef AMIHTTP_USE_AMITLS
    struct TlsContext    *hs_TlsCtx;
    struct TlsConnection *hs_TlsConn;
#else
    APTR                  hs_Ctx;   /* SSL_CTX * */
    APTR                  hs_Ssl;   /* SSL * */
#endif
    STRPTR                hs_Hostname;
    LONG                  hs_Sock;
    BOOL                  hs_Closed;
    /*
     * Set only after a successful TLS handshake (used by callers that care;
     * teardown does not call SSL_shutdown — that can block indefinitely).
     */
    BOOL                  hs_HandshakeOk;
    BOOL                  hs_CertPresent;
    STRPTR                hs_CertSubject;
    STRPTR                hs_CertIssuer;
    STRPTR                hs_CertCommonName;
    STRPTR                hs_CertNotBefore;
    STRPTR                hs_CertNotAfter;
    STRPTR                hs_CertSerial;
    LONG                  hs_CertVerifyResult;
};

VOID ht_ssl_peer_cert_free(struct HtSsl *s);
VOID ht_ssl_peer_cert_copy(struct HttpSslPeerCert *dst, struct HtSsl *s);
VOID ht_ssl_peer_cert_clear(struct HtSsl *s);

#endif /* AMIHTTP_PRIVATE_HT_SSL_H */
