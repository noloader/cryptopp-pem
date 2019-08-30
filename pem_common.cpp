// pem_common.cpp - commom PEM routines.
//                  Written and placed in the public domain by Jeffrey Walton

///////////////////////////////////////////////////////////////////////////
// For documentation on the PEM read and write routines, see
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

#include "cryptlib.h"
#include "secblock.h"
#include "base64.h"
#include "osrng.h"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "pem.h"
#include "pem_common.h"

ANONYMOUS_NAMESPACE_BEGIN

using CryptoPP::byte;

inline const byte* BYTE_PTR(const char* cstr)
{
    return reinterpret_cast<const byte*>(cstr);
}

inline byte* BYTE_PTR(char* cstr)
{
    return reinterpret_cast<byte*>(cstr);
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

const SecByteBlock CR(BYTE_PTR("\r"), 1);
const SecByteBlock LF(BYTE_PTR("\n"), 1);
const SecByteBlock CRLF(BYTE_PTR("\r\n"), 2);
const SecByteBlock RFC1421_EOL(BYTE_PTR("\r\n"), 2);

const SecByteBlock COMMA(BYTE_PTR(","), 1);
const SecByteBlock SPACE(BYTE_PTR(" "), 1);
const SecByteBlock COLON(BYTE_PTR(":"), 1);

const SecByteBlock PEM_BEGIN(BYTE_PTR("-----BEGIN"), 10);
const SecByteBlock PEM_TAIL(BYTE_PTR("-----"), 5);
const SecByteBlock PEM_END(BYTE_PTR("-----END"), 8);

const SecByteBlock PUBLIC_BEGIN(BYTE_PTR("-----BEGIN PUBLIC KEY-----"), 26);
const SecByteBlock PUBLIC_END(BYTE_PTR("-----END PUBLIC KEY-----"), 24);

const SecByteBlock PRIVATE_BEGIN(BYTE_PTR("-----BEGIN PRIVATE KEY-----"), 27);
const SecByteBlock PRIVATE_END(BYTE_PTR("-----END PRIVATE KEY-----"), 25);

const SecByteBlock RSA_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN RSA PUBLIC KEY-----"), 30);
const SecByteBlock RSA_PUBLIC_END(BYTE_PTR("-----END RSA PUBLIC KEY-----"), 28);

const SecByteBlock RSA_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN RSA PRIVATE KEY-----"), 31);
const SecByteBlock RSA_PRIVATE_END(BYTE_PTR("-----END RSA PRIVATE KEY-----"), 29);

const SecByteBlock DSA_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN DSA PUBLIC KEY-----"), 30);
const SecByteBlock DSA_PUBLIC_END(BYTE_PTR("-----END DSA PUBLIC KEY-----"), 28);

const SecByteBlock DSA_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN DSA PRIVATE KEY-----"), 31);
const SecByteBlock DSA_PRIVATE_END(BYTE_PTR("-----END DSA PRIVATE KEY-----"), 29);

const SecByteBlock ELGAMAL_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN ELGAMAL PUBLIC KEY-----"), 34);
const SecByteBlock ELGAMAL_PUBLIC_END(BYTE_PTR("-----END ELGAMAL PUBLIC KEY-----"), 32);

const SecByteBlock ELGAMAL_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN ELGAMAL PRIVATE KEY-----"), 35);
const SecByteBlock ELGAMAL_PRIVATE_END(BYTE_PTR("-----END ELGAMAL PRIVATE KEY-----"), 33);

const SecByteBlock EC_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN EC PUBLIC KEY-----"), 29);
const SecByteBlock EC_PUBLIC_END(BYTE_PTR("-----END EC PUBLIC KEY-----"), 27);

const SecByteBlock ECDSA_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN ECDSA PUBLIC KEY-----"), 32);
const SecByteBlock ECDSA_PUBLIC_END(BYTE_PTR("-----END ECDSA PUBLIC KEY-----"), 30);

const SecByteBlock EC_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN EC PRIVATE KEY-----"), 30);
const SecByteBlock EC_PRIVATE_END(BYTE_PTR("-----END EC PRIVATE KEY-----"), 28);

const SecByteBlock EC_PARAMETERS_BEGIN(BYTE_PTR("-----BEGIN EC PARAMETERS-----"), 29);
const SecByteBlock EC_PARAMETERS_END(BYTE_PTR("-----END EC PARAMETERS-----"), 27);

const SecByteBlock DH_PARAMETERS_BEGIN(BYTE_PTR("-----BEGIN DH PARAMETERS-----"), 29);
const SecByteBlock DH_PARAMETERS_END(BYTE_PTR("-----END DH PARAMETERS-----"), 27);

const SecByteBlock DSA_PARAMETERS_BEGIN(BYTE_PTR("-----BEGIN DSA PARAMETERS-----"), 30);
const SecByteBlock DSA_PARAMETERS_END(BYTE_PTR("-----END DSA PARAMETERS-----"), 28);

const SecByteBlock CERTIFICATE_BEGIN(BYTE_PTR("-----BEGIN CERTIFICATE-----"), 27);
const SecByteBlock CERTIFICATE_END(BYTE_PTR("-----END CERTIFICATE-----"), 25);

const SecByteBlock X509_CERTIFICATE_BEGIN(BYTE_PTR("-----BEGIN X509 CERTIFICATE-----"), 32);
const SecByteBlock X509_CERTIFICATE_END(BYTE_PTR("-----END X509 CERTIFICATE-----"), 30);

const SecByteBlock REQ_CERTIFICATE_BEGIN(BYTE_PTR("-----BEGIN CERTIFICATE REQUEST-----"), 35);
const SecByteBlock REQ_CERTIFICATE_END(BYTE_PTR("-----END CERTIFICATE REQUEST-----"), 33);

const SecByteBlock PROC_TYPE(BYTE_PTR("Proc-Type"), 9);
const SecByteBlock PROC_TYPE_ENC(BYTE_PTR("Proc-Type: 4,ENCRYPTED"), 22);
const SecByteBlock ENCRYPTED(BYTE_PTR("ENCRYPTED"), 9);
const SecByteBlock DEK_INFO(BYTE_PTR("DEK-Info"), 8);
const SecByteBlock CONTENT_DOMAIN(BYTE_PTR("Content-Domain"), 14);

void PEM_WriteLine(BufferedTransformation& bt, const SecByteBlock& line)
{
    bt.Put(line.data(), line.size());
    bt.Put(RFC1421_EOL.data(), RFC1421_EOL.size());
}

void PEM_WriteLine(BufferedTransformation& bt, const std::string& line)
{
    bt.Put(reinterpret_cast<const byte*>(line.data()), line.size());
    bt.Put(RFC1421_EOL.data(), RFC1421_EOL.size());
}

void PEM_Base64Decode(BufferedTransformation& source, BufferedTransformation& dest)
{
    Base64Decoder decoder(new Redirector(dest));
    source.TransferTo(decoder);
    decoder.MessageEnd();
}

void PEM_Base64Encode(BufferedTransformation& source, BufferedTransformation& dest)
{
    Base64Encoder encoder(new Redirector(dest), true, RFC1421_LINE_BREAK);
    source.TransferTo(encoder);
    encoder.MessageEnd();
}

SecByteBlock GetControlField(const SecByteBlock& line)
{
    SecByteBlock::const_iterator it = std::search(line.begin(), line.end(), COLON.begin(), COLON.end());
    if (it != line.end())
    {
        size_t len = it - line.begin();
        return SecByteBlock(line.data(), len);
    }

    return SecByteBlock();
}

SecByteBlock GetControlFieldData(const SecByteBlock& line)
{
    SecByteBlock::const_iterator it = std::search(line.begin(), line.end(), COLON.begin(), COLON.end());
    if (it != line.end() && ++it != line.end())
    {
        size_t len = line.end() - it;
        return SecByteBlock(it, len);
    }

    return SecByteBlock();
}

struct ByteToLower {
    byte operator() (byte val) {
        return (byte)std::tolower((int)(word32)val);
    }
};

// Returns 0 if a match, non-0 otherwise
int CompareNoCase(const SecByteBlock& first, const SecByteBlock& second)
{
    if (first.size() < second.size())
        return -1;
    else if (first.size() > second.size())
        return 1;

    // Same size... compare them....
#if (_MSC_VER >= 1500)
    SecByteBlock t1(first), t2(second);
    std::transform(t1.begin(), t1.end(), stdext::make_checked_array_iterator(t1.begin(), t1.size()), ByteToLower());
    std::transform(t2.begin(), t2.end(), stdext::make_checked_array_iterator(t2.begin(), t2.size()), ByteToLower());
#else
    SecByteBlock t1(first), t2(second);
    std::transform(t1.begin(), t1.end(), t1.begin(), ByteToLower());
    std::transform(t2.begin(), t2.end(), t2.begin(), ByteToLower());
#endif

    // Strings are the same length
    return std::memcmp(t1.begin(), t2.begin(), t2.size());
}

// From crypto/evp/evp_key.h. Signature changed a bit to match Crypto++.
int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
    const unsigned char *salt, const unsigned char* data, size_t dlen,
    size_t count, unsigned char *key, size_t ksize,
    unsigned char *iv, size_t vsize)
{
    unsigned int niv,nkey,nhash;
    unsigned int addmd=0,i;

    nkey=static_cast<unsigned int>(ksize);
    niv = static_cast<unsigned int>(vsize);
    nhash = static_cast<unsigned int>(hash.DigestSize());

    SecByteBlock digest(hash.DigestSize());

    if (data == NULL) return (0);

    for (;;)
    {
        hash.Restart();

        if (addmd++)
            hash.Update(digest.data(), digest.size());

        hash.Update(data, dlen);

        if (salt != NULL)
            hash.Update(salt, OPENSSL_PKCS5_SALT_LEN);

        hash.TruncatedFinal(digest.data(), digest.size());

        for (i=1; i<count; i++)
        {
            hash.Restart();
            hash.Update(digest.data(), digest.size());
            hash.TruncatedFinal(digest.data(), digest.size());
        }

        i=0;
        if (nkey)
        {
            for (;;)
            {
                if (nkey == 0) break;
                if (i == nhash) break;
                if (key != NULL)
                    *(key++)=digest[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != nhash))
        {
            for (;;)
            {
                if (niv == 0) break;
                if (i == nhash) break;
                if (iv != NULL)
                    *(iv++)=digest[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) break;
    }

    return static_cast<int>(ksize);
}

NAMESPACE_END
