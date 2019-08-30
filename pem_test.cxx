// pem_test.cxx - PEM testing routines.
//                Written and placed in the public domain by Jeffrey Walton

#include <string>
#include <iostream>

#include "cryptlib.h"
#include "integer.h"
#include "eccrypto.h"
#include "osrng.h"
#include "files.h"
#include "rsa.h"
#include "dsa.h"
#include "pem.h"

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    bool fail = false;

    try
    {
        RSA::PublicKey k1;
        RSA::PrivateKey k2, k3;
        DSA::PublicKey k4;
        DSA::PrivateKey k5, k6;

        DL_GroupParameters_EC<ECP> p7;
        DL_PublicKey_EC<ECP> k8;
        DL_PrivateKey_EC<ECP> k9, k10;

        // Read from OpenSSL generated key
        {
        std::cout << "Load RSA public key" << std::endl;
        FileSource fs1("rsa-pub.pem", true);
        PEM_Load(fs1, k1);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load RSA private key" << std::endl;
        FileSource fs2("rsa-priv.pem", true);
        PEM_Load(fs2, k2);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load encrypted RSA private key" << std::endl;
        FileSource fs3("rsa-enc-priv.pem", true);
        PEM_Load(fs3, k3, "test", 4);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load DSA public key" << std::endl;
        FileSource fs4("dsa-pub.pem", true);
        PEM_Load(fs4, k4);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load DSA private key" << std::endl;
        FileSource fs5("dsa-priv.pem", true);
        PEM_Load(fs5, k5);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load encrypted DSA private key" << std::endl;
        FileSource fs6("dsa-enc-priv.pem", true);
        PEM_Load(fs6, k6, "test", 4);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load ECP parameters" << std::endl;
        FileSource fs7("ec-params.pem", true);
        PEM_Load(fs7, p7);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load ECP public key" << std::endl;
        FileSource fs8("ec-pub.pem", true);
        PEM_Load(fs8, k8);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load ECP private key" << std::endl;
        FileSource fs9("ec-priv.pem", true);
        PEM_Load(fs9, k9);
        std::cout << "  - OK" << std::endl;

        std::cout << "Load encrypted ECP private key" << std::endl;
        FileSource fs10("ec-enc-priv.pem", true);
        PEM_Load(fs10, k10, "test", 4);
        std::cout << "  - OK" << std::endl;
        }

        // Write for OpenSSL to verify
        {
        AutoSeededRandomPool prng;

        std::cout << "Save RSA public key" << std::endl;
        FileSink fs1("rsa-pub.new.pem");
        PEM_Save(fs1, k1);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save RSA private key" << std::endl;
        FileSink fs2("rsa-priv.new.pem");
        PEM_Save(fs2, k2);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save encrypted RSA private key" << std::endl;
        FileSink fs3("rsa-enc-priv.new.pem");
        PEM_Save(fs3, k3, prng, "AES-128-CBC", "test", 4);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save DSA public key" << std::endl;
        FileSink fs4("dsa-pub.new.pem");
        PEM_Save(fs4, k4);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save DSA private key" << std::endl;
        FileSink fs5("dsa-priv.new.pem");
        PEM_Save(fs5, k5);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save encrypted DSA private key" << std::endl;
        FileSink fs6("dsa-enc-priv.new.pem");
        PEM_Save(fs6, k6, prng, "AES-128-CBC", "test", 4);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save ECP parameters" << std::endl;
        FileSink fs7("ec-params.new.pem", true);
        PEM_Save(fs7, p7);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save ECP public key" << std::endl;
        FileSink fs8("ec-pub.new.pem", true);
        PEM_Save(fs8, k8);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save ECP private key" << std::endl;
        FileSink fs9("ec-priv.new.pem", true);
        PEM_Save(fs9, k9);
        std::cout << "  - OK" << std::endl;

        std::cout << "Save encrypted ECP private key" << std::endl;
        FileSink fs10("ec-enc-priv.new.pem", true);
        PEM_Save(fs10, k10, prng, "AES-128-CBC", "test", 4);
        std::cout << "  - OK" << std::endl;
        }
    }
    catch(const Exception& ex)
    {
        std::cout << "Caught exception: " << ex.what() << std::endl;
        fail = true;
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
        fail = true;
    }

    // Load malformed, tampered encapsulation boundary
    try
    {
        RSA::PublicKey k2;
        std::cout << "Load malformed key 2" << std::endl;
        FileSource fs2("rsa-trunc-2.pem", true);
        PEM_Load(fs2, k2);
        std::cout << "  - Failed" << std::endl;
        fail = true;
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
        fail = true;
    }

    // Load malformed, only -----BEGIN RSA KEY-----
    try
    {
        RSA::PublicKey k4;
        std::cout << "Load malformed key 4" << std::endl;
        FileSource fs4("rsa-short.pem", true);
        PEM_Load(fs4, k4);
        std::cout << "  - Failed" << std::endl;
        fail = true;
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
        fail = true;
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
        fail = true;
    }

    // Load malformed, no EOL, should be OK
    try
    {
        RSA::PublicKey k7;
        std::cout << "Load malformed key 7" << std::endl;
        FileSource fs7("rsa-eol-none.pem", true);
        PEM_Load(fs7, k7);
        std::cout << "  - OK" << std::endl;
    }
    catch(const Exception& ex)
    {
        std::cout << "  - Failed" << std::endl;
        fail = true;
    }

    // Load malformed, -----BEGIN FOO----- and -----END BAR-----
    try
    {
        RSA::PublicKey k8;
        std::cout << "Load malformed key 8" << std::endl;
        FileSource fs8("foobar.pem", true);
        PEM_Load(fs8, k8);
        std::cout << "  - Failed" << std::endl;
        fail = true;
    }
    catch(const Exception& ex)
    {
        std::cout << "  - OK" << std::endl;
    }

    // Test cacert.pem. There should be ~130 to ~150 certs in it.
    try
    {
        FileSource fs("cacert.pem", true);
        size_t count=0;

        while (PEM_NextObject(fs, TheBitBucket())) {
            count++;
        }

        std::cout << "Parsed " << count << " certificates from cacert.pem" << std::endl;
        if (count >= 120)
            std::cout << "  - OK" << std::endl;
        else {
            std::cout << "  - Failed" << std::endl;
            fail = true;
        }
    }
    catch(const Exception& ex)
    {
        std::cout << "Caught exception: " << ex.what() << std::endl;
        fail = true;
    }

    return fail ? 1 : 0;
}

