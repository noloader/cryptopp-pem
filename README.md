## Crypto++ PEM Pack

This repository provides PEM parsing for Wei Dai's Crypto++ (https://github.com/weidai11/cryptopp). The source files allow you to read and write keys and parameters in PEM format. PEM is specified in RFC 1421, [Privacy Enhancement for Internet Electronic Mail](https://www.ietf.org/rfc/rfc1421.txt).

The PEM format uses an encapsulation header which describes the algorithm used to encrypt or authenticate the message. The encapsulated header uses BEGIN and END to frame it. The message is Base64 encoded. Lines are limited to 64 characters, and the end-of-line is CR ('\r') and LF ('\n').

There is a wiki page available at [PEM Pack](https://www.cryptopp.com/wiki/PEM_Pack).

The files are officialy unsupported, so use it at your own risk.
