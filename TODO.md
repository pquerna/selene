If you want to work on any of these or something else, just let selene-dev@googlegroups.com know.

Current TODO:

* Add Certificate Store interface
 * Search for cert by:
  * CN, subjectAltName, dnsName, etc
  * fingerprint

* Build extractor / easy way to get the trusted certificate list from chrome into a header file.
 * Should be able to be invoked as a build target, ie, 'scons update-trusted-certs'
 * Download the latest CAs from some place on the internet, and then rewrite a sln_trusted_certs.h

* Alert message handling (parsing is done)
 * If Fatal, cleanup to mark the selene_t as dead, return a selene_error_t from all API surfaces.
 * Several TODOs throughout the parse about sending fatal alerts / shutting down the connection, this needs work.

* Parse all handshake message types (see lib/parser/handshake_messages.c):
 * hello_request(0) [ignore]
 * client_hello(1) [done]
 * server_hello(2) [done]
 * certificate(11) [WIP]
 * server_key_exchange(12)
 * certificate_request(13)
 * server_hello_done(14)
 * certificate_verify(15)
 * client_key_exchange(16)
 * finished(20)

* Finish handshake state machine (send correct replies to everything we get)
 * Implement ChangeCiphers
 * Plugable Backend Wrappers for, initially using OpenSSL:
  * Ciphers: AES, RC4
  * RSA
  * SHA1, SHA256, MD5

* TLS-PSK support
