/*
 * ht_ssl_common.c - Shared peer-certificate string helpers (both TLS backends)
 */

#define __USE_SYSBASE

#include <exec/types.h>

#include <libraries/amihttp.h>

#include "private/ht_internal.h"
#include "private/ht_ssl.h"

VOID
ht_ssl_peer_cert_free(struct HtSsl *s)
{
    if (s == NULL) {
        return;
    }
    if (s->hs_CertSubject) {
        ht_free(s->hs_CertSubject);
    }
    if (s->hs_CertIssuer) {
        ht_free(s->hs_CertIssuer);
    }
    if (s->hs_CertCommonName) {
        ht_free(s->hs_CertCommonName);
    }
    if (s->hs_CertNotBefore) {
        ht_free(s->hs_CertNotBefore);
    }
    if (s->hs_CertNotAfter) {
        ht_free(s->hs_CertNotAfter);
    }
    if (s->hs_CertSerial) {
        ht_free(s->hs_CertSerial);
    }
    s->hs_CertSubject = NULL;
    s->hs_CertIssuer = NULL;
    s->hs_CertCommonName = NULL;
    s->hs_CertNotBefore = NULL;
    s->hs_CertNotAfter = NULL;
    s->hs_CertSerial = NULL;
    s->hs_CertPresent = FALSE;
    s->hs_CertVerifyResult = 0;
}

VOID
ht_ssl_peer_cert_copy(struct HttpSslPeerCert *dst, struct HtSsl *s)
{
    if (dst == NULL) {
        return;
    }
    dst->hpc_Subject = NULL;
    dst->hpc_Issuer = NULL;
    dst->hpc_CommonName = NULL;
    dst->hpc_NotBefore = NULL;
    dst->hpc_NotAfter = NULL;
    dst->hpc_Serial = NULL;
    dst->hpc_VerifyResult = 0;
    if (s == NULL || !s->hs_CertPresent) {
        return;
    }
    if (s->hs_CertSubject) {
        dst->hpc_Subject = ht_strdup(s->hs_CertSubject);
    }
    if (s->hs_CertIssuer) {
        dst->hpc_Issuer = ht_strdup(s->hs_CertIssuer);
    }
    if (s->hs_CertCommonName) {
        dst->hpc_CommonName = ht_strdup(s->hs_CertCommonName);
    }
    if (s->hs_CertNotBefore) {
        dst->hpc_NotBefore = ht_strdup(s->hs_CertNotBefore);
    }
    if (s->hs_CertNotAfter) {
        dst->hpc_NotAfter = ht_strdup(s->hs_CertNotAfter);
    }
    if (s->hs_CertSerial) {
        dst->hpc_Serial = ht_strdup(s->hs_CertSerial);
    }
    dst->hpc_VerifyResult = s->hs_CertVerifyResult;
}

VOID
ht_ssl_peer_cert_clear(struct HtSsl *s)
{
    ht_ssl_peer_cert_free(s);
}
