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

    const std::string defaultPassword   = "test";
    const std::string defaultAlgorithm  = "AES-128-CBC";

    try
    {
        std::cout << "Load RSA public key" << std::endl;
        FileSource fs1( "rsa-pub.pem", true );
        RSA::PublicKey rsaPubKey;
        PEM_Load( fs1, rsaPubKey );

        std::cout << "Load RSA private key" << std::endl;
        FileSource fs2( "rsa-priv.pem", true );
        RSA::PrivateKey rsaPrivKey;
        PEM_Load( fs2, rsaPrivKey );

        std::cout << "Load encrypted RSA private key" << std::endl;
        FileSource fs3( "rsa-enc-priv.pem", true );
        RSA::PrivateKey rsaEncPrivKey;
        PEM_Load( fs3, rsaEncPrivKey, defaultPassword.c_str(), defaultPassword.length() );

        std::cout << "Load DSA parameters" << std::endl;
        FileSource fs4( "dsa-params.pem", true );
        DL_GroupParameters_DSA dsaParams;
        PEM_Load( fs4, dsaParams );

        std::cout << "Load DSA public key" << std::endl;
        FileSource fs5( "dsa-pub.pem", true );
        DSA::PublicKey dsaPubKey;
        PEM_Load( fs5, dsaPubKey );

        std::cout << "Load DSA private key" << std::endl;
        FileSource fs6( "dsa-priv.pem", true );
        DSA::PrivateKey dsaPrivKey;
        PEM_Load( fs6, dsaPrivKey );

        std::cout << "Load encrypted DSA private key" << std::endl;
        FileSource fs7( "dsa-enc-priv.pem", true );
        DSA::PrivateKey dsaEncPrivKey;
        PEM_Load( fs7, dsaEncPrivKey, defaultPassword.c_str(), defaultPassword.length() );

        std::cout << "Load EC parameters" << std::endl;
        FileSource fs8( "ec-params.pem", true );
        DL_GroupParameters_EC<ECP> ecParams;
        PEM_Load( fs8, ecParams );

        std::cout << "Load EC public key" << std::endl;
        FileSource fs9( "ec-pub.pem", true );
        DL_PublicKey_EC<ECP> ecPubKey;
        PEM_Load( fs9, ecPubKey );

        std::cout << "Load EC private key" << std::endl;
        FileSource fs10( "ec-priv.pem", true );
        DL_PrivateKey_EC<ECP> ecPrivKey;
        PEM_Load( fs10, ecPrivKey );

        std::cout << "Load encrypted EC private key" << std::endl;
        FileSource fs11( "ec-enc-priv.pem", true );
        DL_PrivateKey_EC<ECP> ecEncPrivKey;
        PEM_Load( fs11, ecEncPrivKey, defaultPassword.c_str(), defaultPassword.length() );

        std::cout << "Save RSA public key" << std::endl;
        FileSink fs12( "rsa-pub-xxx.pem", true );
        PEM_Save( fs12, rsaPubKey );

        std::cout << "Save RSA private key" << std::endl;
        FileSink fs13( "rsa-priv-xxx.pem", true );
        PEM_Save( fs13, rsaPrivKey );

        std::cout << "Save encrypted RSA private key" << std::endl;
        FileSink fs14( "rsa-enc-priv-xxx.pem", true );
        AutoSeededRandomPool rsaPrng;
        PEM_Save( fs14, rsaPrng, rsaEncPrivKey, defaultAlgorithm.c_str(), defaultPassword.c_str(), defaultPassword.length() );

        std::cout << "Save DSA parameters" << std::endl;
        FileSink fs15( "dsa-params-xxx.pem", true );
        PEM_Save( fs15, dsaParams );

        std::cout << "Save DSA public key" << std::endl;
        FileSink fs16( "dsa-pub-xxx.pem", true );
        PEM_Save( fs16, dsaPubKey );

        std::cout << "Save DSA private key" << std::endl;
        FileSink fs17( "dsa-priv-xxx.pem", true );
        PEM_Save( fs17, dsaPrivKey );

        std::cout << "Save encrypted DSA private key" << std::endl;
        FileSink fs18( "dsa-enc-priv-xxx.pem", true );
        AutoSeededRandomPool dsaPrng;
        PEM_Save( fs18, dsaPrng, dsaEncPrivKey, defaultAlgorithm.c_str(), defaultPassword.c_str(), defaultPassword.length() );

        std::cout << "Save EC parameters" << std::endl;
        FileSink fs19( "ec-params-xxx.pem", true );
        PEM_Save( fs19, ecParams );

        std::cout << "Save EC public key" << std::endl;
        FileSink fs20( "ec-pub-xxx.pem" );
        PEM_Save( fs20, ecPubKey );

        std::cout << "Save EC private key" << std::endl;
        FileSink fs21( "ec-priv-xxx.pem", true );
        PEM_Save( fs21, ecPrivKey );

        std::cout << "Save encrypted EC private key" << std::endl;
        FileSink fs22( "ec-enc-priv-xxx.pem", true );
        AutoSeededRandomPool ecPrng;
        PEM_Save( fs22, ecPrng, ecEncPrivKey, defaultAlgorithm.c_str(), defaultPassword.c_str(), defaultPassword.length() );
    }
    catch(const Exception& ex)
    {
        std::cout << "Caught exception : " << ex.what() << std::endl;
    }

    return 0;
}
