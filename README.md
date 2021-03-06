# Selene - A SSL/TLS library

Selene has a few goals that makes it different from a more traditional 
SSL libraries:

* Completely Asynchronous: Selene does no IO itself, it only provides
notifications to the user that IO should be done.

* Asynchronous Callbacks: Callback functions provide their own callback
to notify Selene when the user has finished an operation.

* Test Driven: A test framework to test all code paths.

* Plugable Backends for Cryptography: Currently only focusing
on OpenSSL, but others are possible.

* Liberal License: Under the Apache License, version 2.0.

Selene is named after the [Greek Goddess of the Moon](http://en.wikipedia.org/wiki/Selene),
because I am terrible at naming projects.

# Status

A prototype backend (openssl-threaded) was used to validate the basics
of the selene_* API.  I am currently slowly working on the native Selene
TLS backend, which only uses OpenSSL for cryptographic operations, but
not the actual protocol parsing.

# Hacking Notes:

* All contributors must sign an [Apache Software Foundation CLA](http://www.apache.org/licenses/icla.txt),
and agree that Selene may be moved to the ASF at a future date.
* External Functions and types are prefixed with selene_*
* Internal Functions and types are prefixed with sln_*
* Style: [Google C++ Style Guide](http://google-styleguide.googlecode.com/svn/trunk/cppguide.xml), even though this is C. Use `clang-format -style=Google` on all source code.
* Write test cases for all code paths, including errors.
