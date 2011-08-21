If you want to work on any of these or something else, just let selene-dev@googlegroups.com know.

Current TODO:

* Grep the source code for TODO; There are a ton.

* Improve debug logging.  If we had bug reports, I couldn't fix the from debug logs right now.

* Parse all handshake message types (see lib/parser/handshake_messages.h):
 * hello_request(0) [ignore]
 * client_hello(1) [done]
 * server_hello(2) [done]
 * certificate(11) [done]
 * server_key_exchange(12)
 * certificate_request(13)
 * server_hello_done(14) [done]
 * certificate_verify(15)
 * client_key_exchange(16) [wip]
 * finished(20) [wip]

* Add bindings to various crypto operations, on both OpenSSL and OSX's CommonCrypto:
 * Digest [done]
 * HMAC [done]
 * RSA [wip; need OSX-CommonCrypto]
 * AES
 * RC4

# Longer term thoughts

* Improve Alert message handling (parsing is done)
 * If Fatal, cleanup to mark the selene_t as dead, return a selene_error_t from all API surfaces.
 * Several TODOs throughout the parse about sending fatal alerts / shutting down the connection, this needs work.

* Add Certificate Store interface
 * Search for cert by:
  * CN, subjectAltName, dnsName, etc
  * fingerprint

* Build extractor / easy way to get the trusted certificate list from chrome into a header file.
 * Should be able to be invoked as a build target, ie, 'scons update-trusted-certs'
 * Download the latest CAs from some place on the internet, and then rewrite a sln_trusted_certs.h

* Implement next protocol negotiation <http://tools.ietf.org/html/draft-agl-tls-nextprotoneg-02>:
 * see NextProtos <http://golang.org/src/pkg/crypto/tls/common.go?s=2940:4315#L97>
   since the RFC does not provide information about the format of this data.
 * Client Hello send empty extension_data
 * Server Hello respond with available protocols
 * Protocol selection event / completion callback

* Implement SessionTickets <http://www.rfc-editor.org/rfc/rfc5077.txt>

* OCSP API
 * Make it internal or just say you are up a creek?
 * General Validation API
  * Callback? Connect to server X? Send this payload? Pump me the reply?
 * Think about server-OCSP-stapling (is stapling going to be DOA in the real world anyways?)

* Finish handshake state machine (send correct replies to everything we get)
 * Implement ChangeCiphers

* TLS-PSK support
