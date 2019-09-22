## Crypto++ PEM Pack

This repository provides PEM parsing for Wei Dai's [Crypto++](https://github.com/weidai11/cryptopp). The source files allow you to read and write keys and parameters in PEM format. PEM is specified in RFC 1421, [Privacy Enhancement for Internet Electronic Mail](https://www.ietf.org/rfc/rfc1421.txt).

To compile the source files drop them in your `cryptopp` directory and run `make`. The makefile will automatically pick them up. Visual Studio users should add the source files to the `cryptlib` project. Detailed information can be found at [PEM Pack](https://www.cryptopp.com/wiki/PEM_Pack) on the Crypto++ wiki.

The PEM format uses an encapsulation header which describes the algorithm used to encrypt or authenticate the message. The encapsulated header uses BEGIN and END to frame the message. The message is Base64 encoded, lines are limited to 64 characters, and the end-of-line is CR ('\r') and LF ('\n').

The files are officialy unsupported, so use it at your own risk.

# ZIP Files

If you are working from a Crypto++ release zip file, then you should download the same cryptopp-pem release zip file. Both Crypto++ and this project use the same release tags, such as CRYPTOPP_8_2_0.

If you mix and match Master with a release zip file then things may not work as expected. You may find the build project files reference a source file that is not present in the Crypto++ release.
