// pem_test.cxx - PEM testing routines.
//                Written and placed in the public domain by Jeffrey Walton

#include <string>
#include <iostream>
#include <cstdlib>

#include "cryptlib.h"
#include "integer.h"
#include "eccrypto.h"
#include "osrng.h"
#include "files.h"
#include "rsa.h"
#include "dsa.h"
#include "pem.h"

// Define this to 1 to enable the DSA private key tests. OpenSSL 3.0 changed the on-disk
// format from Traditional to PKCS#8, and there does not seem to be a way to get it back.
// Also see <https://github.com/openssl/openssl/issues/23497>.

#define ENABLE_DSA_PRIVATE_KEY_TESTS 0

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    std::string filename;

    try
    {
        RSA::PublicKey k1;
        RSA::PrivateKey k2, k3;

        DSA::PublicKey k4;
#if ENABLE_DSA_PRIVATE_KEY_TESTS
        DSA::PrivateKey k5, k6;
#endif

        DL_GroupParameters_EC<ECP> p7;
        DL_PublicKey_EC<ECP> k8;
        DL_PrivateKey_EC<ECP> k9, k10;

        // Read from OpenSSL generated key
        {
            std::cout << "Load RSA public key" << std::endl;
            filename = "rsa-pub.pem";
            FileSource fs1("rsa-pub.pem", true);
            PEM_Load(fs1, k1);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load RSA private key" << std::endl;
            filename = "rsa-priv.pem";
            FileSource fs2("rsa-priv.pem", true);
            PEM_Load(fs2, k2);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load encrypted RSA private key" << std::endl;
            filename = "rsa-enc-priv.pem";
            FileSource fs3("rsa-enc-priv.pem", true);
            PEM_Load(fs3, k3, "abcdefghijklmnopqrstuvwxyz", 26);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load DSA public key" << std::endl;
            filename = "dsa-pub.pem";
            FileSource fs4("dsa-pub.pem", true);
            PEM_Load(fs4, k4);
            std::cout << "  - OK" << std::endl;

#if ENABLE_DSA_PRIVATE_KEY_TESTS
            std::cout << "Load DSA private key" << std::endl;
            filename = "dsa-priv.pem";
            FileSource fs5("dsa-priv.pem", true);
            PEM_Load(fs5, k5);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load encrypted DSA private key" << std::endl;
            filename = "dsa-enc-priv.pem";
            FileSource fs6("dsa-enc-priv.pem", true);
            PEM_Load(fs6, k6, "abcdefghijklmnopqrstuvwxyz", 26);
            std::cout << "  - OK" << std::endl;
#else
            std::cout << "Load DSA private key" << std::endl;
            std::cout << "  - Skipped due to OpenSSL 3.0" << std::endl;

            std::cout << "Load encrypted DSA private key" << std::endl;
            std::cout << "  - Skipped due to OpenSSL 3.0" << std::endl;
#endif

            std::cout << "Load ECP parameters" << std::endl;
            filename = "ec-params.pem";
            FileSource fs7("ec-params.pem", true);
            PEM_Load(fs7, p7);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load ECP public key" << std::endl;
            filename = "ec-pub.pem";
            FileSource fs8("ec-pub.pem", true);
            PEM_Load(fs8, k8);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load ECP private key" << std::endl;
            filename = "ec-priv.pem";
            FileSource fs9("ec-priv.pem", true);
            PEM_Load(fs9, k9);
            std::cout << "  - OK" << std::endl;

            std::cout << "Load encrypted ECP private key" << std::endl;
            filename = "ec-enc-priv.pem";
            FileSource fs10("ec-enc-priv.pem", true);
            PEM_Load(fs10, k10, "abcdefghijklmnopqrstuvwxyz", 26);
            std::cout << "  - OK" << std::endl;
        }

        // Write for OpenSSL to verify
        {
            AutoSeededRandomPool prng;

            std::cout << "Save RSA public key" << std::endl;
            filename = "rsa-pub.cryptopp.pem";
            FileSink fs1("rsa-pub.cryptopp.pem");
            PEM_Save(fs1, k1);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save RSA private key" << std::endl;
            filename = "rsa-priv.cryptopp.pem";
            FileSink fs2("rsa-priv.cryptopp.pem");
            PEM_Save(fs2, k2);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save encrypted RSA private key" << std::endl;
            filename = "rsa-enc-priv.cryptopp.pem";
            FileSink fs3("rsa-enc-priv.cryptopp.pem");
            PEM_Save(fs3, k3, prng, "AES-128-CBC", "abcdefghijklmnopqrstuvwxyz", 26);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save DSA public key" << std::endl;
            filename = "dsa-pub.cryptopp.pem";
            FileSink fs4("dsa-pub.cryptopp.pem");
            PEM_Save(fs4, k4);
            std::cout << "  - OK" << std::endl;

#if ENABLE_DSA_PRIVATE_KEY_TESTS
            std::cout << "Save DSA private key" << std::endl;
            filename = "dsa-priv.cryptopp.pem";
            FileSink fs5("dsa-priv.cryptopp.pem");
            PEM_Save(fs5, k5);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save encrypted DSA private key" << std::endl;
            filename = "dsa-enc-priv.cryptopp.pem";
            FileSink fs6("dsa-enc-priv.cryptopp.pem");
            PEM_Save(fs6, k6, prng, "AES-128-CBC", "abcdefghijklmnopqrstuvwxyz", 26);
            std::cout << "  - OK" << std::endl;
#else
            std::cout << "Save DSA private key" << std::endl;
            std::cout << "  - Skipped due to OpenSSL 3.0" << std::endl;

            std::cout << "Save encrypted DSA private key" << std::endl;
            std::cout << "  - Skipped due to OpenSSL 3.0" << std::endl;
#endif

            std::cout << "Save ECP parameters" << std::endl;
            filename = "ec-params.cryptopp.pem";
            FileSink fs7("ec-params.cryptopp.pem", true);
            PEM_Save(fs7, p7);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save ECP public key" << std::endl;
            filename = "ec-pub.cryptopp.pem";
            FileSink fs8("ec-pub.cryptopp.pem", true);
            PEM_Save(fs8, k8);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save ECP private key" << std::endl;
            filename = "ec-priv.cryptopp.pem";
            FileSink fs9("ec-priv.cryptopp.pem", true);
            PEM_Save(fs9, k9);
            std::cout << "  - OK" << std::endl;

            std::cout << "Save encrypted ECP private key" << std::endl;
            filename = "ec-enc-priv.cryptopp.pem";
            FileSink fs10("ec-enc-priv.cryptopp.pem", true);
            PEM_Save(fs10, k10, prng, "AES-128-CBC", "abcdefghijklmnopqrstuvwxyz", 26);
            std::cout << "  - OK" << std::endl;
        }
    }
    catch(const Exception& ex)
    {
        std::cout << "Caught exception: " << ex.what() << " while processing " << filename << std::endl;
        std::exit(1);
    }

    // Load malformed, missing final CRLF, should be OK
    try
    {
        RSA::PublicKey k1;
        std::cout << "Load malformed key 1" << std::endl;
        FileSource fs1("rsa-trunc-1.pem", true);
        PEM_Load(fs1, k1);
        std::cout << "  - OK" << std::endl;
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }

    // Load malformed, tampered encapsulation boundary
    try
    {
        RSA::PublicKey k2;
        std::cout << "Load malformed key 2" << std::endl;
        FileSource fs2("rsa-trunc-2.pem", true);
        PEM_Load(fs2, k2);
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }
    catch(const Exception& ex)
    {
        std::cout << "  - OK" << std::endl;
    }

    // Load malformed, missing final CRLF, another key concat'd, should be OK
    try
    {
        RSA::PublicKey k3;
        std::cout << "Load malformed key 3" << std::endl;
        FileSource fs3("rsa-concat.pem", true);
        PEM_Load(fs3, k3);
        std::cout << "  - OK" << std::endl;
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }

    // Load malformed, only -----BEGIN RSA KEY-----
    try
    {
        RSA::PublicKey k4;
        std::cout << "Load malformed key 4" << std::endl;
        FileSource fs4("rsa-short.pem", true);
        PEM_Load(fs4, k4);
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }
    catch(const Exception& ex)
    {
        std::cout << "  - OK" << std::endl;
    }

    // Load malformed, EOL is CR, should be OK
    try
    {
        RSA::PublicKey k5;
        std::cout << "Load malformed key 5" << std::endl;
        FileSource fs5("rsa-eol-cr.pem", true);
        PEM_Load(fs5, k5);
        std::cout << "  - OK" << std::endl;
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }

    // Load malformed, EOL is LF, should be OK
    try
    {
        RSA::PublicKey k6;
        std::cout << "Load malformed key 6" << std::endl;
        FileSource fs6("rsa-eol-lf.pem", true);
        PEM_Load(fs6, k6);
        std::cout << "  - OK" << std::endl;
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }

    // Load malformed, no EOL, should fail due
    // to no EOL on encapsulation boundaries
    try
    {
        RSA::PublicKey k7;
        std::cout << "Load malformed key 7" << std::endl;
        FileSource fs7("rsa-eol-none.pem", true);
        PEM_Load(fs7, k7);
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }
    catch(const Exception& ex)
    {
        std::cout << "  - OK" << std::endl;
    }

    // Load malformed, -----BEGIN FOO----- and -----END BAR-----
    try
    {
        RSA::PublicKey k8;
        std::cout << "Load malformed key 8" << std::endl;
        FileSource fs8("foobar.pem", true);
        PEM_Load(fs8, k8);
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }
    catch(const Exception& ex)
    {
        std::cout << "  - OK" << std::endl;
    }

    // Read the Let's Encrypt cert for www.cryptopp.com
    {
        try {
            std::cout << "\nLoad Let's Encrypt cert for www.cryptopp.com" << std::endl;

            X509Certificate cert;
            FileSource fs("www-cryptopp-com.cert.pem", true);
            PEM_Load(fs, cert);

            std::cout << "  - OK" << std::endl;

            std::cout << "\nDumping certificate:" << std::endl;
            std::cout << cert << std::endl;

            std::cout << "\nDumping identities:" << std::endl;
            std::cout << cert.GetSubjectIdentities() << std::endl;
        }
        catch(const Exception& ex) {
            std::cout << "Caught exception: " << ex.what() << std::endl;
            std::exit(1);
        }
    }

    // Read the OpenSSL generated self-signed end-entity cert for example.com
    {
        try {
            std::cout << "\nLoad X.509 example-com.cert.pem certificate" << std::endl;

            X509Certificate cert;
            FileSource fs("example-com.cert.pem", true);
            PEM_Load(fs, cert);

            std::cout << "  - OK" << std::endl;

            std::cout << "\nDumping certificate:" << std::endl;
            std::cout << cert << std::endl;

            std::cout << "\nDumping identities:" << std::endl;
            std::cout << cert.GetSubjectIdentities() << std::endl;
        }
        catch(const Exception& ex) {
            std::cout << "Caught exception: " << ex.what() << std::endl;
            std::exit(1);
        }
    }

    // Malformed.
    try
    {
        X509Certificate cert;
        std::cout << "\nLoad malformed X.509 certificate" << std::endl;
        const std::string pem =
            "-----BEGIN CERTIFICATE-----\r\n"
            "MIIE+TCCA+GgAwIBAgIURIR"
            "-----END CERTIFICATE-----\r\n";
        ArraySource source(pem, true);
        PEM_Load(source, cert);
        std::cout << "  - Failed" << std::endl;
        std::exit(1);
    }
    catch(const Exception& ex)
    {
        std::cout << "  - OK" << std::endl;
    }

    // Test cacert.pem from Mozilla.
    // There should be ~130 to ~150 certs in it.
    try
    {
        std::cout << "\nLoad root certificates from Mozilla" << std::endl;

        FileSource fs("./cacert.pem", true);
        ByteQueue t;
        size_t count=0;

        while (PEM_NextObject(fs, t))
        {
            count++;  // 1-based

            X509Certificate cert;
            std::ostringstream oss;

            try {
                PEM_Load(t, cert);
                oss << cert << std::endl;
            }
            catch (const Exception&) {
                std::cerr << "Failed to parse certificate " << count << std::endl;

                std::cerr << "\nWriting certificate badcert.der" << std::endl;
                FileSink x("badcert.der");
                cert.WriteCertificateBytes(x);

                std::cerr << "\nDumping certificate" << std::endl;
                std::cerr << oss.str() << std::endl;
                throw;
            }

            AutoSeededRandomPool prng;
            if (cert.Validate(prng, 2) == false)
            {
                std::ostringstream message;
                message << "Failed to validate public key for " << cert.GetSubjectDistinguishedName();
                std::cerr << message.str() << std::endl;;

                std::cerr << "\nWriting certificate badcert.der" << std::endl;
                FileSink x("badcert.der");
                cert.WriteCertificateBytes(x);

                std::cerr << "\nDumping certificate" << std::endl;
                std::cerr << oss.str() << std::endl;

                throw Exception(Exception::OTHER_ERROR, message.str());
            }
        }

        if (count >= 120) {
            std::cout << "  - OK (" << count << " certificates)" << std::endl;
        }
        else {
            std::cout << "  - Failed (died at certificate " << count << ")" << std::endl;
            std::exit(1);
        }
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Exception: " << ex.what() << std::endl;
        std::exit(1);
    }

    // Test roots.pem from Google.
    // There should be ~35 to ~40 certs in it.
    try
    {
        std::cout << "\nLoad root certificates from Google" << std::endl;

        FileSource fs("./roots.pem", true);
        ByteQueue t;
        size_t count=0;

        while (PEM_NextObject(fs, t))
        {
            count++;  // 1-based

            X509Certificate cert;
            std::ostringstream oss;

            try {
                PEM_Load(t, cert);
                oss << cert << std::endl;
            }
            catch (const Exception&) {
                std::cerr << "Failed to parse certificate " << count << std::endl;

                std::cerr << "\nWriting certificate badcert.der" << std::endl;
                FileSink x("badcert.der");
                cert.WriteCertificateBytes(x);

                std::cerr << "\nDumping certificate" << std::endl;
                std::cerr << oss.str() << std::endl;
                throw;
            }

            AutoSeededRandomPool prng;
            if (cert.Validate(prng, 2) == false)
            {
                std::ostringstream message;
                message << "Failed to validate public key for " << cert.GetSubjectDistinguishedName();
                std::cerr << message.str() << std::endl;;

                std::cerr << "\nWriting certificate badcert.der" << std::endl;
                FileSink x("badcert.der");
                cert.WriteCertificateBytes(x);

                std::cerr << "\nDumping certificate" << std::endl;
                std::cerr << oss.str() << std::endl;

                throw Exception(Exception::OTHER_ERROR, message.str());
            }
        }

        if (count >= 30) {
            std::cout << "  - OK (" << count << " certificates)" << std::endl;
        }
        else {
            std::cout << "  - Failed (died at certificate " << count << ")" << std::endl;
            std::exit(1);
        }
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Exception: " << ex.what() << std::endl;
        std::exit(1);
    }

    return 0;
}
