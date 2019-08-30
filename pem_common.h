// pem_common.h - commom PEM routines.
//                Written and placed in the public domain by Jeffrey Walton
//                pem_common.h is an internal header. Include pem.h instead.

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
NAMESPACE_BEGIN(PEM)

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

// By default, keys and parameters are validated after reading in Debug builds.
//   You will have to call key.Validate() yourself if desired. If you want automatic
//   validation, then uncomment the line below or set it on the command line.
// #define PEM_KEY_OR_PARAMETER_VALIDATION 1

#if defined(CRYPTOPP_DEBUG) && !defined(PEM_KEY_OR_PARAMETER_VALIDATION)
# define PEM_KEY_OR_PARAMETER_VALIDATION 1
#endif

//////////////////////////////////////////////////////
//////////////////////////////////////////////////////

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

// Signals failure
static const size_t PEM_INVALID = static_cast<size_t>(-1);

// 64-character line length is required by RFC 1421.
static const unsigned int PEM_LINE_BREAK = 64;

extern const SecByteBlock CR;
extern const SecByteBlock LF;
extern const SecByteBlock EOL;
extern const SecByteBlock CRLF;

extern const SecByteBlock COMMA;
extern const SecByteBlock SPACE;
extern const SecByteBlock COLON;

extern const SecByteBlock PEM_BEGIN;
extern const SecByteBlock PEM_TAIL;
extern const SecByteBlock PEM_END;

extern const SecByteBlock PUBLIC_BEGIN;
extern const SecByteBlock PUBLIC_END;

extern const SecByteBlock PRIVATE_BEGIN;
extern const SecByteBlock PRIVATE_END;

extern const SecByteBlock RSA_PUBLIC_BEGIN;
extern const SecByteBlock RSA_PUBLIC_END;

extern const SecByteBlock RSA_PRIVATE_BEGIN;
extern const SecByteBlock RSA_PRIVATE_END;

extern const SecByteBlock DSA_PUBLIC_BEGIN;
extern const SecByteBlock DSA_PUBLIC_END;

extern const SecByteBlock DSA_PRIVATE_BEGIN;
extern const SecByteBlock DSA_PRIVATE_END;

extern const SecByteBlock ELGAMAL_PUBLIC_BEGIN;
extern const SecByteBlock ELGAMAL_PUBLIC_END;

extern const SecByteBlock ELGAMAL_PRIVATE_BEGIN;
extern const SecByteBlock ELGAMAL_PRIVATE_END;

extern const SecByteBlock EC_PUBLIC_BEGIN;
extern const SecByteBlock EC_PUBLIC_END;

extern const SecByteBlock ECDSA_PUBLIC_BEGIN;
extern const SecByteBlock ECDSA_PUBLIC_END;

extern const SecByteBlock EC_PRIVATE_BEGIN;
extern const SecByteBlock EC_PRIVATE_END;

extern const SecByteBlock EC_PARAMETERS_BEGIN;
extern const SecByteBlock EC_PARAMETERS_END;

extern const SecByteBlock DH_PARAMETERS_BEGIN;
extern const SecByteBlock DH_PARAMETERS_END;

extern const SecByteBlock DSA_PARAMETERS_BEGIN;
extern const SecByteBlock DSA_PARAMETERS_END;

extern const SecByteBlock CERTIFICATE_BEGIN;
extern const SecByteBlock CERTIFICATE_END;

extern const SecByteBlock X509_CERTIFICATE_BEGIN;
extern const SecByteBlock X509_CERTIFICATE_END;

extern const SecByteBlock REQ_CERTIFICATE_BEGIN;
extern const SecByteBlock REQ_CERTIFICATE_END;

extern const SecByteBlock PROC_TYPE;
extern const SecByteBlock PROC_TYPE_ENC;
extern const SecByteBlock ENCRYPTED;
extern const SecByteBlock DEK_INFO;
extern const SecByteBlock CONTENT_DOMAIN;

NAMESPACE_END  // PEM
NAMESPACE_END  // CryptoPP

#endif // CRYPTOPP_PEM_COM_H
