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
		PEM_Save(fs3, prng, k3, "AES-128-CBC", "test", 4);
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
		PEM_Save(fs6, prng, k6, "AES-128-CBC", "test", 4);
		std::cout << "  - OK" << std::endl;

		std::cout << "Save ECP parameters" << std::endl;
		FileSink fs7("ec-params.new.pem", true);
		PEM_Save(fs7, p7);
		std::cout << "  - OK" << std::endl;

		std::cout << "Save ECP public key" << std::endl;
		FileSink fs8("ec-pub.new.pem", true);
		PEM_Save(fs8, k8);

		std::cout << "Save ECP private key" << std::endl;
		FileSink fs9("ec-priv.new.pem", true);
		PEM_Save(fs9, k9);
		std::cout << "  - OK" << std::endl;

		std::cout << "Save encrypted ECP private key" << std::endl;
		FileSink fs10("ec-enc-priv.new.pem", true);
		PEM_Save(fs10, prng, k10, "AES-128-CBC", "test", 4);
		std::cout << "  - OK" << std::endl;
	}

	// Test cacert.pem. There should be ~130 or ~140 certs in it.
	{
		FileSource fs("cacert.pem", true);
		size_t count=0;

		while (PEM_NextObject(fs, TheBitBucket())) {
			count++;
		}

		std::cout << "Parsed " << count << " certificates from cacert.pem" << std::endl;
		std::cout << "  - OK" << std::endl;
	}

        // Save an EC public key
        //FileSink fs16("ec-pub-xxx.pem", true);
        //DL_PublicKey_EC<ECP> k16;
        //PEM_Save(fs16, k16);

        // Save an encrypted EC private key
        //AutoSeededRandomPool prng;
        //DL_PrivateKey_EC<ECP> k18 = ...;
        //FileSink fs18("ec-enc-priv-xxx.pem", true);
        //PEM_Save(fs18, prng, k18, "AES-128-CBC", "test", 4);
    }
    catch(const Exception& ex)
    {
        std::cout << "Caught exception: " << ex.what() << std::endl;
    }

    return 0;
}
