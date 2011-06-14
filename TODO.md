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

* Parse all handshake message types

* Finish handshake state machine (send correct replies to everything we get)
 * Implement ChangeCiphers.....  (complicated, needs MAC over Handshake Messges for TLS 1.2)


