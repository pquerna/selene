Current TODO:

* Parse all handshake message types 

* Finish handshake state machine 
  (send correct replies to everything we get) 

* Add Certificate Store interface (Search for cert by 
  CN for SNI, CA  chains, etc) 

* Implement ChangeCiphers.....  (complicated, needs MAC over Handshake Messges for TLS 1.2)

* Alert message handling (parsing is done)

* Implement aes-sha and rc4-sha for app data encrytion.

* fix bugs 

