/*
 * ht_ssl_config.h - TLS backend selection for amihttp.library
 *
 * Default build uses AmiSSL (OpenSSL).  To build against amitls.library instead,
 * add to Source/lib_source/SCOPTIONS:
 *
 *   DEFINE=AMIHTTP_USE_AMITLS
 *
 * or copy SCOPTIONS.amitls over SCOPTIONS before smake, or:
 *
 *   smake AMIHTTP_USE_AMITLS=1
 *
 * AmiSSL build needs netinclude: and sslinclude: on INCLUDEDIR (see SCOPTIONS).
 * amitls build needs amitls SDK headers (see SCOPTIONS.amitls).
 */

#ifndef AMIHTTP_PRIVATE_HT_SSL_CONFIG_H
#define AMIHTTP_PRIVATE_HT_SSL_CONFIG_H

/* AMIHTTP_USE_AMITLS may be set via SCOPTIONS DEFINE= or smake define= */

#endif /* AMIHTTP_PRIVATE_HT_SSL_CONFIG_H */
