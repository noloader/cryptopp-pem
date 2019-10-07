// badcert.cxx is a test program built in pem_create_keys.sh
// pem_create_keys.sh and pem_verify_keys.sh verify the
// PEM source files and X509Certificate class. If
// X509Certificate has a problem with a cert, like a CA cert,
// then it writes the cert to badcert.der. badcert.exe then
// reads the cert and attempts to parse it. badcert.exe is
// the prebuilt stand alone reproducer.

#include "cryptlib.h"
#include "x509cert.h"
#include "secblock.h"
#include "filters.h"
#include "files.h"
#include "osrng.h"
#include "rsa.h"
#include "sha.h"
#include "hex.h"
#include "pem.h"

#include <iostream>
#include <string>

extern const std::string pemCertificate;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    FileSource fs("badcert.der", true);
    X509Certificate cert;
    cert.Load(fs);

    const SecByteBlock& signature = cert.GetCertificateSignature();
    const SecByteBlock& toBeSigned = cert.GetToBeSigned();
    const X509PublicKey& publicKey = cert.GetSubjectPublicKey();
    const OID &signAlgorithm = cert.GetCertificateSignatureAlgorithm();

    AutoSeededRandomPool prng;
    bool result1 = publicKey.Validate(prng, 3);

    member_ptr<PK_Verifier> verifier;
    bool ecSignature = false, result2;

    if (signAlgorithm == id_sha1WithRSASignature)
    {
        verifier.reset(new RSASS<PKCS1v15, SHA1>::Verifier(publicKey));
    }
    else if (signAlgorithm == id_sha256WithRSAEncryption)
    {
        verifier.reset(new RSASS<PKCS1v15, SHA256>::Verifier(publicKey));
    }
    else if (signAlgorithm == id_sha384WithRSAEncryption)
    {
        verifier.reset(new RSASS<PKCS1v15, SHA384>::Verifier(publicKey));
    }
    else if (signAlgorithm == id_sha512WithRSAEncryption)
    {
        verifier.reset(new RSASS<PKCS1v15, SHA512>::Verifier(publicKey));
    }
    else if (signAlgorithm == id_ecdsaWithSHA256)
    {
        verifier.reset(new ECDSA<ECP, SHA256>::Verifier(publicKey));
        ecSignature = true;
    }
    else if (signAlgorithm == id_ecdsaWithSHA384)
    {
        verifier.reset(new ECDSA<ECP, SHA384>::Verifier(publicKey));
        ecSignature = true;
    }
    else if (signAlgorithm == id_ecdsaWithSHA512)
    {
        verifier.reset(new ECDSA<ECP, SHA512>::Verifier(publicKey));
        ecSignature = true;
    }
    else
    {
        CRYPTOPP_ASSERT(0);
    }

    if (ecSignature)
    {
        size_t size = verifier->MaxSignatureLength();
        SecByteBlock ecSignature(size);

        size = DSAConvertSignatureFormat(
            ecSignature, ecSignature.size(), DSA_P1363,
            signature, signature.size(), DSA_DER);
        ecSignature.resize(size);

        result2 = verifier->VerifyMessage(toBeSigned, toBeSigned.size(), ecSignature, ecSignature.size());
    }
    else
    {
        result2 = verifier->VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());
    }

    if (result1)
        std::cout << "Verified public key" << std::endl;
    else
        std::cout << "Failed to verify public key" << std::endl;

    if (result2)
        std::cout << "Verified certificate" << std::endl;
    else
        std::cout << "Failed to verify certificate" << std::endl;

    std::cout << std::endl;

    std::cout << "Signature: ";
    size_t size = std::min(signature.size(), (size_t)30);
    StringSource(signature, size, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "..." << std::endl;

    std::cout << "To Be Signed: ";
    size = std::min(signature.size(), (size_t)30);
    StringSource(toBeSigned, size, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << "..." << std::endl;

    std::cout << cert << std::endl;
    std::cout << std::endl;

    return 0;
}
