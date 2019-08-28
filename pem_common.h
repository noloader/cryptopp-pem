// pem-com.h - commom PEM routines. Written and placed in the public domain by Jeffrey Walton
//             Copyright assigned to the Crypto++ project.
//
// Crypto++ Library is copyrighted as a compilation and (as of version 5.6.2) licensed
// under the Boost Software License 1.0, while the individual files in the compilation
// are all public domain.

///////////////////////////////////////////////////////////////////////////
// For documentation on the PEM read and write routines, see
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

#ifndef CRYPTOPP_PEM_COM_H
#define CRYPTOPP_PEM_COM_H

#include "cryptlib.h"
#include "secblock.h"
#include "osrng.h"
#include "pem.h"

#include <string>

NAMESPACE_BEGIN(CryptoPP)

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

// By default, keys and parameters are validated after reading in Debug builds.
//   You will have to call key.Validate() yourself if desired. If you want automatic
//   validation, then uncomment the line below or set it on the command line.
// #define PEM_KEY_OR_PARAMETER_VALIDATION 1

// Perform key or parameter validation in Debug builds.
#if !defined(NDEBUG) && !defined(PEM_KEY_OR_PARAMETER_VALIDATION)
# define PEM_KEY_OR_PARAMETER_VALIDATION 1
#endif

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

inline const byte* BYTE_PTR(const char* cstr)
{
    return reinterpret_cast<const byte*>(cstr);
}

inline byte* BYTE_PTR(char* cstr)
{
    return reinterpret_cast<byte*>(cstr);
}

// Attempts to locate a control field in a line
SecByteBlock GetControlField(const SecByteBlock& line);

// Attempts to fetch the data from a control line
SecByteBlock GetControlFieldData(const SecByteBlock& line);

// Returns 0 if a match, non-0 otherwise
int CompareNoCase(const SecByteBlock& first, const SecByteBlock& second);

// Base64 Encode
void PEM_Base64Encode(BufferedTransformation& source, BufferedTransformation& dest);

// Base64 Decode
void PEM_Base64Decode(BufferedTransformation& source, BufferedTransformation& dest);

// Write to a BufferedTransformation
void PEM_WriteLine(BufferedTransformation& bt, const std::string& line);
void PEM_WriteLine(BufferedTransformation& bt, const SecByteBlock& line);

// Signature changed a bit to match Crypto++. Salt must be PKCS5_SALT_LEN in length.
//  Salt, Data and Count are IN; Key and IV are OUT.
int OPENSSL_EVP_BytesToKey(HashTransformation& hash,
                           const unsigned char *salt, const unsigned char* data, size_t dlen,
                           size_t count, unsigned char *key, size_t ksize,
                           unsigned char *iv, size_t vsize);

// From OpenSSL, crypto/evp/evp.h.
static const unsigned int OPENSSL_PKCS5_SALT_LEN = 8;

// 64-character line length is required by RFC 1421.
static const unsigned int RFC1421_LINE_BREAK = 64;
static const std::string RFC1421_EOL = "\r\n";

// Signals failure
static const size_t PEM_INVALID = static_cast<size_t>(-1);

static const SecByteBlock CR(BYTE_PTR("\r"), 1);
static const SecByteBlock LF(BYTE_PTR("\n"), 1);
static const SecByteBlock CRLF(BYTE_PTR("\r\n"), 2);

static const SecByteBlock COMMA(BYTE_PTR(","), 1);
static const SecByteBlock SPACE(BYTE_PTR(" "), 1);
static const SecByteBlock COLON(BYTE_PTR(":"), 1);

static const SecByteBlock PEM_BEGIN(BYTE_PTR("-----BEGIN"), 10);
static const SecByteBlock PEM_TAIL(BYTE_PTR("-----"), 5);
static const SecByteBlock PEM_END(BYTE_PTR("-----END"), 8);

static const SecByteBlock PUBLIC_BEGIN(BYTE_PTR("-----BEGIN PUBLIC KEY-----"), 26);
static const SecByteBlock PUBLIC_END(BYTE_PTR("-----END PUBLIC KEY-----"), 24);

static const SecByteBlock PRIVATE_BEGIN(BYTE_PTR("-----BEGIN PRIVATE KEY-----"), 27);
static const SecByteBlock PRIVATE_END(BYTE_PTR("-----END PRIVATE KEY-----"), 25);

static const SecByteBlock RSA_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN RSA PUBLIC KEY-----"), 30);
static const SecByteBlock RSA_PUBLIC_END(BYTE_PTR("-----END RSA PUBLIC KEY-----"), 28);

static const SecByteBlock RSA_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN RSA PRIVATE KEY-----"), 31);
static const SecByteBlock RSA_PRIVATE_END(BYTE_PTR("-----END RSA PRIVATE KEY-----"), 29);

static const SecByteBlock DSA_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN DSA PUBLIC KEY-----"), 30);
static const SecByteBlock DSA_PUBLIC_END(BYTE_PTR("-----END DSA PUBLIC KEY-----"), 28);

static const SecByteBlock DSA_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN DSA PRIVATE KEY-----"), 31);
static const SecByteBlock DSA_PRIVATE_END(BYTE_PTR("-----END DSA PRIVATE KEY-----"), 28);

static const SecByteBlock ELGAMAL_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN ELGAMAL PUBLIC KEY-----"), 34);
static const SecByteBlock ELGAMAL_PUBLIC_END(BYTE_PTR("-----END ELGAMAL PUBLIC KEY-----"), 32);

static const SecByteBlock ELGAMAL_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN ELGAMAL PRIVATE KEY-----"), 35);
static const SecByteBlock ELGAMAL_PRIVATE_END(BYTE_PTR("-----END ELGAMAL PRIVATE KEY-----"), 33);

static const SecByteBlock EC_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN EC PUBLIC KEY-----"), 29);
static const SecByteBlock EC_PUBLIC_END(BYTE_PTR("-----END EC PUBLIC KEY-----"), 27);

static const SecByteBlock ECDSA_PUBLIC_BEGIN(BYTE_PTR("-----BEGIN ECDSA PUBLIC KEY-----"), 32);
static const SecByteBlock ECDSA_PUBLIC_END(BYTE_PTR("-----END ECDSA PUBLIC KEY-----"), 30);

static const SecByteBlock EC_PRIVATE_BEGIN(BYTE_PTR("-----BEGIN EC PRIVATE KEY-----"), 30);
static const SecByteBlock EC_PRIVATE_END(BYTE_PTR("-----END EC PRIVATE KEY-----"), 28);

static const SecByteBlock EC_PARAMETERS_BEGIN(BYTE_PTR("-----BEGIN EC PARAMETERS-----"), 29);
static const SecByteBlock EC_PARAMETERS_END(BYTE_PTR("-----END EC PARAMETERS-----"), 27);

static const SecByteBlock DH_PARAMETERS_BEGIN(BYTE_PTR("-----BEGIN DH PARAMETERS-----"), 29);
static const SecByteBlock DH_PARAMETERS_END(BYTE_PTR("-----END DH PARAMETERS-----"), 27);

static const SecByteBlock DSA_PARAMETERS_BEGIN(BYTE_PTR("-----BEGIN DSA PARAMETERS-----"), 30);
static const SecByteBlock DSA_PARAMETERS_END(BYTE_PTR("-----END DSA PARAMETERS-----"), 28);

static const SecByteBlock CERTIFICATE_BEGIN(BYTE_PTR("-----BEGIN CERTIFICATE-----"), 27);
static const SecByteBlock CERTIFICATE_END(BYTE_PTR("-----END CERTIFICATE-----"), 25);

static const SecByteBlock X509_CERTIFICATE_BEGIN(BYTE_PTR("-----BEGIN X509 CERTIFICATE-----"), 32);
static const SecByteBlock X509_CERTIFICATE_END(BYTE_PTR("-----END X509 CERTIFICATE-----"), 30);

static const SecByteBlock REQ_CERTIFICATE_BEGIN(BYTE_PTR("-----BEGIN CERTIFICATE REQUEST-----"), 35);
static const SecByteBlock REQ_CERTIFICATE_END(BYTE_PTR("-----END CERTIFICATE REQUEST-----"), 33);

static const SecByteBlock PROC_TYPE(BYTE_PTR("Proc-Type"), 9);
static const SecByteBlock PROC_TYPE_ENC(BYTE_PTR("Proc-Type: 4,ENCRYPTED"), 22);
static const SecByteBlock ENCRYPTED(BYTE_PTR("ENCRYPTED"), 9);
static const SecByteBlock DEK_INFO(BYTE_PTR("DEK-Info"), 8);
static const SecByteBlock CONTENT_DOMAIN(BYTE_PTR("Content-Domain"), 14);

NAMESPACE_END

#endif // CRYPTOPP_PEM_COM_H
