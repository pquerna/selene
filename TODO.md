Current TODO:

* Parse all handshake message types 

* Finish handshake state machine 
  (send correct replies to everything we get) 

* Add Certificate Store interface (Search for cert by 
  CN for SNI, CA  chains, etc) (some framing in place)

* Build extractor / easy way to get the trusted certificate list from chrome into a header file.
   (should be able to be invoked as a build target, ie, 'scons update-trusted-certs' and download
    the latest CAs from some place on the internet, and then rewrite a sln_trusted_certs.h)

* Implement ChangeCiphers.....  (complicated, needs MAC over Handshake Messges for TLS 1.2)

* Alert message handling (parsing is done)

* Implement aes-sha and rc4-sha for app data encrytion.

* fix bugs 

