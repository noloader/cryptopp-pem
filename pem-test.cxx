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
        std::cout << "Load RSA public key" << std::endl;
        FileSource fs1("rsa-pub.pem", true);
        RSA::PublicKey k1;
        PEM_Load(fs1, k1);

        std::cout << "Load RSA private key" << std::endl;
        FileSource fs2("rsa-priv.pem", true);
        RSA::PrivateKey k2;
        PEM_Load(fs2, k2);

        std::cout << "Load encrypted RSA private key" << std::endl;
        FileSource fs3("rsa-enc-priv.pem", true);
        RSA::PrivateKey k3;
        PEM_Load(fs3, k3, "test", 4);

        std::cout << "Load DSA public key" << std::endl;
        FileSource fs4("dsa-pub.pem", true);
        DSA::PublicKey k4;
        PEM_Load(fs4, k4);

        std::cout << "Load DSA private key" << std::endl;
        FileSource fs5("dsa-priv.pem", true);
        DSA::PrivateKey k5;
        PEM_Load(fs5, k5);

        std::cout << "Load encrypted DSA private key" << std::endl;
        FileSource fs6("dsa-enc-priv.pem", true);
        DSA::PrivateKey k6;
        PEM_Load(fs6, k6, "test", 4);

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
        std::cout << "Caught excpetion" << ex.what() << std::endl;
    }

    return 0;
}
