// pem_read.cpp - PEM read routines.
//                Written and placed in the public domain by Jeffrey Walton

///////////////////////////////////////////////////////////////////////////
// For documentation on the PEM read and write routines, see
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

#include <string>
#include <algorithm>
#include <cctype>

#include "cryptlib.h"
#include "secblock.h"
#include "nbtheory.h"
#include "gfpcrypt.h"
#include "camellia.h"
#include "smartptr.h"
#include "filters.h"
#include "base64.h"
#include "queue.h"
#include "modes.h"
#include "asn.h"
#include "aes.h"
#include "idea.h"
#include "hex.h"

#include "pem.h"
#include "pem_common.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "des.h"
#include "md5.h"

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

ANONYMOUS_NAMESPACE_BEGIN

using namespace CryptoPP;
using namespace CryptoPP::PEM;

// Info from the encapsulated header
struct EncapsulatedHeader
{
    std::string m_version;
    std::string m_operation;
    std::string m_algorithm;

    std::string m_iv;
};

// GCC 9 compile error using overload PEM_GetType
PEM_Type PEM_GetTypeFromBlock(const SecByteBlock& sb);

size_t PEM_ReadLine(BufferedTransformation& source, SecByteBlock& line, SecByteBlock& ending);

void PEM_StripEncapsulatedBoundary(BufferedTransformation& bt, const SecByteBlock& pre, const SecByteBlock& post);
void PEM_StripEncapsulatedBoundary(SecByteBlock& sb, const SecByteBlock& pre, const SecByteBlock& post);

void PEM_StripEncapsulatedHeader(BufferedTransformation& src, BufferedTransformation& dest, EncapsulatedHeader& header);

void PEM_CipherForAlgorithm(const EncapsulatedHeader& header,
                            const char* password, size_t length,
                            member_ptr<StreamTransformation>& stream);

void PEM_DecodeAndDecrypt(BufferedTransformation& src, BufferedTransformation& dest,
                          const char* password, size_t length);
void PEM_Decrypt(BufferedTransformation& src, BufferedTransformation& dest,
                 member_ptr<StreamTransformation>& stream);

bool PEM_IsEncrypted(SecByteBlock& sb);
bool PEM_IsEncrypted(BufferedTransformation& bt);

void PEM_ParseVersion(const std::string& proctype, std::string& version);
void PEM_ParseOperation(const std::string& proctype, std::string& operation);

void PEM_ParseAlgorithm(const std::string& dekinfo, std::string& algorithm);
void PEM_ParseIV(const std::string& dekinfo, std::string& iv);

inline SecByteBlock::const_iterator Search(const SecByteBlock& source, const SecByteBlock& target);

template <class EC>
void PEM_LoadParams(BufferedTransformation& bt, DL_GroupParameters_EC<EC>& params);

void PEM_LoadPublicKey(BufferedTransformation& bt, X509PublicKey& key, bool subjectInfo = false);
void PEM_LoadPrivateKey(BufferedTransformation& bt, PKCS8PrivateKey& key, bool subjectInfo = false);

// Crypto++ expects {version,x}; OpenSSL writes {version,x,y,p,q,g}
void PEM_LoadPrivateKey(BufferedTransformation& bt, DSA::PrivateKey& key);

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

SecByteBlock::const_iterator Search(const SecByteBlock& source, const SecByteBlock& target)
{
    return std::search(source.begin(), source.end(), target.begin(), target.end());
}

PEM_Type PEM_GetTypeFromBlock(const SecByteBlock& sb)
{
    SecByteBlock::const_iterator it;

    // Uses an OID to identify the public key type
    it = Search(sb, PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_PUBLIC_KEY;

    // Uses an OID to identify the private key type
    it = Search(sb, PRIVATE_BEGIN);
    if (it != sb.end())
        return PEM_PRIVATE_KEY;

    // RSA key types
    it = Search(sb, RSA_PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_RSA_PUBLIC_KEY;

    it = Search(sb, RSA_PRIVATE_BEGIN);
    if (it != sb.end())
    {
        it = Search(sb, PROC_TYPE_ENC);
        if (it != sb.end())
            return PEM_RSA_ENC_PRIVATE_KEY;

        return PEM_RSA_PRIVATE_KEY;
    }

    // DSA key types
    it = Search(sb, DSA_PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_DSA_PUBLIC_KEY;

    it = Search(sb, DSA_PRIVATE_BEGIN);
    if (it != sb.end())
    {
        it = Search(sb, PROC_TYPE_ENC);
        if (it != sb.end())
            return PEM_DSA_ENC_PRIVATE_KEY;

        return PEM_DSA_PRIVATE_KEY;
    }

    // ElGamal key types
    it = Search(sb, ELGAMAL_PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_ELGAMAL_PUBLIC_KEY;

    it = Search(sb, ELGAMAL_PRIVATE_BEGIN);
    if (it != sb.end())
    {
        it = Search(sb, PROC_TYPE_ENC);
        if (it != sb.end())
            return PEM_ELGAMAL_ENC_PRIVATE_KEY;

        return PEM_ELGAMAL_PRIVATE_KEY;
    }

    // EC key types
    it = Search(sb, EC_PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_EC_PUBLIC_KEY;

    it = Search(sb, ECDSA_PUBLIC_BEGIN);
    if (it != sb.end())
        return PEM_ECDSA_PUBLIC_KEY;

    it = Search(sb, EC_PRIVATE_BEGIN);
    if (it != sb.end())
    {
        it = Search(sb, PROC_TYPE_ENC);
        if (it != sb.end())
            return PEM_EC_ENC_PRIVATE_KEY;

        return PEM_EC_PRIVATE_KEY;
    }

    // EC Parameters
    it = Search(sb, EC_PARAMETERS_BEGIN);
    if (it != sb.end())
        return PEM_EC_PARAMETERS;

    // DH Parameters
    it = Search(sb, DH_PARAMETERS_BEGIN);
    if (it != sb.end())
        return PEM_DH_PARAMETERS;

    // DSA Parameters
    it = Search(sb, DSA_PARAMETERS_BEGIN);
    if (it != sb.end())
        return PEM_DSA_PARAMETERS;

    // Certificate
    it = Search(sb, CERTIFICATE_BEGIN);
    if (it != sb.end())
        return PEM_CERTIFICATE;

    it = Search(sb, X509_CERTIFICATE_BEGIN);
    if (it != sb.end())
        return PEM_X509_CERTIFICATE;

    it = Search(sb, REQ_CERTIFICATE_BEGIN);
    if (it != sb.end())
        return PEM_REQ_CERTIFICATE;

    return PEM_UNSUPPORTED;
}

void PEM_LoadPublicKey(BufferedTransformation& src, X509PublicKey& key, bool subjectInfo)
{
    X509PublicKey& pk = dynamic_cast<X509PublicKey&>(key);

    if (subjectInfo)
        pk.Load(src);
    else
        pk.BERDecode(src);

#if defined(PEM_KEY_OR_PARAMETER_VALIDATION) && !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if (!pk.Validate(prng, 2))
        throw Exception(Exception::OTHER_ERROR, "PEM_LoadPublicKey: key validation failed");
#endif
}

void PEM_LoadPrivateKey(BufferedTransformation& src, PKCS8PrivateKey& key, bool subjectInfo)
{
    if (subjectInfo)
        key.Load(src);
    else
        key.BERDecodePrivateKey(src, 0, src.MaxRetrievable());

#if defined(PEM_KEY_OR_PARAMETER_VALIDATION) && !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if (!key.Validate(prng, 2))
        throw Exception(Exception::OTHER_ERROR, "PEM_LoadPrivateKey: key validation failed");
#endif
}

void PEM_LoadPrivateKey(BufferedTransformation& bt, DSA::PrivateKey& key)
{
    // Crypto++ expects {version,x}, while OpenSSL provides {version,p,q,g,y,x}.
    BERSequenceDecoder seq(bt);

    word32 v;
    BERDecodeUnsigned<word32>(seq, v, INTEGER, 0, 0);  // check version

    Integer p,q,g,y,x;

    p.BERDecode(seq);
    q.BERDecode(seq);
    g.BERDecode(seq);
    y.BERDecode(seq);
    x.BERDecode(seq);

    seq.MessageEnd();

    key.Initialize(p, q, g, x);

#if defined(PEM_KEY_OR_PARAMETER_VALIDATION) && !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if (!key.Validate(prng, 2))
        throw Exception(Exception::OTHER_ERROR, "PEM_LoadPrivateKey: key validation failed");
#endif
}

template < class EC >
void PEM_LoadParams(BufferedTransformation& bt, DL_GroupParameters_EC<EC>& params)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_EC_PARAMETERS)
        PEM_StripEncapsulatedBoundary(obj, EC_PARAMETERS_BEGIN, EC_PARAMETERS_END);
    else
        throw InvalidDataFormat("PEM_Read: invalid EC parameters");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    params.BERDecode(temp);
}

bool PEM_IsEncrypted(SecByteBlock& sb)
{
    SecByteBlock::iterator it = std::search(sb.begin(), sb.end(), PROC_TYPE.begin(), PROC_TYPE.end());
    if (it == sb.end()) return false;

    it = std::search(it + PROC_TYPE.size(), sb.end(), ENCRYPTED.begin(), ENCRYPTED.end());
    return it != sb.end();
}

bool PEM_IsEncrypted(BufferedTransformation& bt)
{
    const size_t size = bt.MaxRetrievable();
    SecByteBlock sb(size);
    bt.Peek(sb.data(), sb.size());

    return PEM_IsEncrypted(sb);
}

void PEM_CipherForAlgorithm(const EncapsulatedHeader& header,
                            const char* password, size_t length,
                            member_ptr<StreamTransformation>& stream)
{
    unsigned int ksize, vsize;

    std::string algorithm(header.m_algorithm);
    std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(),  (int(*)(int))std::toupper);

    if (algorithm == "AES-256-CBC")
    {
        ksize = 32;
        vsize = 16;

        stream.reset(new CBC_Mode<AES>::Decryption);
    }
    else if (algorithm == "AES-192-CBC")
    {
        ksize = 24;
        vsize = 16;

        stream.reset(new CBC_Mode<AES>::Decryption);
    }
    else if (algorithm == "AES-128-CBC")
    {
        ksize = 16;
        vsize = 16;

        stream.reset(new CBC_Mode<AES>::Decryption);
    }
    else if (algorithm == "CAMELLIA-256-CBC")
    {
        ksize = 32;
        vsize = 16;

        stream.reset(new CBC_Mode<Camellia>::Decryption);
    }
    else if (algorithm == "CAMELLIA-192-CBC")
    {
        ksize = 24;
        vsize = 16;

        stream.reset(new CBC_Mode<Camellia>::Decryption);
    }
    else if (algorithm == "CAMELLIA-128-CBC")
    {
        ksize = 16;
        vsize = 16;

        stream.reset(new CBC_Mode<Camellia>::Decryption);
    }
    else if (algorithm == "DES-EDE3-CBC")
    {
        ksize = 24;
        vsize = 8;

        stream.reset(new CBC_Mode<DES_EDE3>::Decryption);
    }
    else if (algorithm == "DES-EDE2-CBC")
    {
        ksize = 16;
        vsize = 8;

        stream.reset(new CBC_Mode<DES_EDE2>::Decryption);
    }
    else if (algorithm == "DES-CBC")
    {
        ksize = 8;
        vsize = 8;

        stream.reset(new CBC_Mode<DES>::Decryption);
    }
    else if (algorithm == "IDEA-CBC")
    {
        ksize = 16;
        vsize = 8;

        stream.reset(new CBC_Mode<IDEA>::Decryption);
    }
    else
    {
        throw NotImplemented("PEM_CipherForAlgorithm: '" + header.m_algorithm + "' is not implemented");
    }

    // Decode the IV. It used as the Salt in EVP_BytesToKey,
    //   and its used as the IV in the cipher.
    HexDecoder hex;
    hex.Put((const byte*)header.m_iv.data(), header.m_iv.size());
    hex.MessageEnd();

    // If the IV size is wrong, SetKeyWithIV will throw an exception.
    size_t size = hex.MaxRetrievable();
    size = (std::min)(size, static_cast<size_t>(vsize));

    SecByteBlock _key(ksize);
    SecByteBlock _iv(size);
    SecByteBlock _salt(size);

    hex.Get(_iv.data(), _iv.size());

    // The IV pulls double duty. First, the first PKCS5_SALT_LEN bytes are used
    //   as the Salt in EVP_BytesToKey. Second, its used as the IV in the cipher.
    _salt = _iv;

    // MD5 is engrained OpenSSL goodness. MD5, IV and Password are IN; KEY is OUT.
    //   {NULL,0} parameters are the OUT IV. However, the original IV in the PEM
    //   header is used; and not the derived IV.
    Weak::MD5 md5;
    int ret = OPENSSL_EVP_BytesToKey(md5, _iv.data(), (const byte*)password, length, 1, _key.data(), _key.size(), NULL, 0);
    if (ret != static_cast<int>(ksize))
        throw Exception(Exception::OTHER_ERROR, "PEM_CipherForAlgorithm: EVP_BytesToKey failed");

    SymmetricCipher* cipher = dynamic_cast<SymmetricCipher*>(stream.get());
    cipher->SetKeyWithIV(_key.data(), _key.size(), _iv.data(), _iv.size());
}

void PEM_DecodeAndDecrypt(BufferedTransformation& src, BufferedTransformation& dest,
                          const char* password, size_t length)
{
    ByteQueue temp1;
    EncapsulatedHeader header;
    PEM_StripEncapsulatedHeader(src, temp1, header);

    ByteQueue temp2;
    PEM_Base64Decode(temp1, temp2);

    member_ptr<StreamTransformation> stream;
    PEM_CipherForAlgorithm(header, password, length, stream);

    PEM_Decrypt(temp2, dest, stream);
}

void PEM_Decrypt(BufferedTransformation& src, BufferedTransformation& dest,
                 member_ptr<StreamTransformation>& stream)
{
    try
    {
        StreamTransformationFilter filter(*stream, new Redirector(dest));
        src.TransferTo(filter);
        filter.MessageEnd();
    }
    catch (const Exception& ex)
    {
        std::string message(ex.what());
        size_t pos = message.find(":");
        if (pos != std::string::npos && pos+2 < message.size())
            message = message.substr(pos+2);

        throw Exception(Exception::OTHER_ERROR, std::string("PEM_Decrypt: ") + message);
    }
}

void PEM_StripEncapsulatedBoundary(BufferedTransformation& bt, const SecByteBlock& pre, const SecByteBlock& post)
{
    ByteQueue temp;
    SecByteBlock::const_iterator it;
    int n = 1, prePos = -1, postPos = -1;

    while (bt.AnyRetrievable() && n++)
    {
        SecByteBlock line, unused;
        PEM_ReadLine(bt, line, unused);

        // The write associated with an empty line must occur. Otherwise, we loose the CR or LF
        //    in an ecrypted private key between the control fields and the encapsulated text.
        //if (line.empty())
        //    continue;

        it = Search(line, pre);
        if (it != line.end())
        {
            prePos = n;
            continue;
        }
        it = Search(line, post);
        if (it != line.end())
        {
            postPos = n;
            continue;
        }

        PEM_WriteLine(temp, line);
    }

    if (prePos == -1)
    {
        std::string msg = "PEM_StripEncapsulatedBoundary: '";
        msg += std::string((char*)pre.data(), pre.size()) + "' not found";
        throw InvalidDataFormat(msg);
    }

    if (postPos == -1)
    {
        std::string msg = "PEM_StripEncapsulatedBoundary: '";
        msg += std::string((char*)post.data(), post.size()) + "' not found";
        throw InvalidDataFormat(msg);
    }

    if (prePos > postPos)
        throw InvalidDataFormat("PEM_StripEncapsulatedBoundary: header boundary follows footer boundary");

    temp.TransferTo(bt);
}

void PEM_StripEncapsulatedHeader(BufferedTransformation& src, BufferedTransformation& dest, EncapsulatedHeader& header)
{
    if (!src.AnyRetrievable())
        return;

    SecByteBlock line, ending;
    size_t size = 0;

    // The first line *must* be Proc-Type. Ensure we read it before dropping into the loop.
    size = PEM_ReadLine(src, line, ending);
    if (size == 0 || line.empty())
        throw InvalidDataFormat("PEM_StripEncapsulatedHeader: failed to locate Proc-Type");

    SecByteBlock field = GetControlField(line);
    if (field.empty())
        throw InvalidDataFormat("PEM_StripEncapsulatedHeader: failed to locate Proc-Type");

    if (0 != CompareNoCase(field, PROC_TYPE))
        throw InvalidDataFormat("PEM_StripEncapsulatedHeader: failed to locate Proc-Type");

    line = GetControlFieldData(line);
    std::string tline(reinterpret_cast<const char*>(line.data()),line.size());

    PEM_ParseVersion(tline, header.m_version);
    if (header.m_version != "4")
        throw NotImplemented("PEM_StripEncapsulatedHeader: encryption version " + header.m_version + " not supported");

    PEM_ParseOperation(tline, header.m_operation);
    if (header.m_operation != "ENCRYPTED")
        throw NotImplemented("PEM_StripEncapsulatedHeader: operation " + header.m_operation + " not supported");

    // Next, we have to read until the first empty line
    while (true)
    {
        if (!src.AnyRetrievable()) break; // End Of Buffer

        size = PEM_ReadLine(src, line, ending);
        if (size == 0) break;        // End Of Buffer
        if (line.size() == 0) break; // size is non-zero; empty line

        field = GetControlField(line);
        if (0 == CompareNoCase(field, DEK_INFO))
        {
            line = GetControlFieldData(line);
            tline = std::string(reinterpret_cast<const char*>(line.data()),line.size());

            PEM_ParseAlgorithm(tline, header.m_algorithm);
            PEM_ParseIV(tline, header.m_iv);

            continue;
        }

        if (0 == CompareNoCase(field, CONTENT_DOMAIN))
        {
            // Silently ignore
            // Content-Domain: RFC822
            continue;
        }

        if (!field.empty())
        {
            const char* ptr = (char*)field.begin();
            size_t len = field.size();

            std::string m(ptr, len);
            throw NotImplemented("PEM_StripEncapsulatedHeader: " + m + " not supported");
        }
    }

    if (header.m_algorithm.empty())
        throw InvalidArgument("PEM_StripEncapsulatedHeader: no encryption algorithm");

    if (header.m_iv.empty())
        throw InvalidArgument("PEM_StripEncapsulatedHeader: no IV present");

    // After the empty line is the encapsulated text. Transfer it to the destination.
    src.TransferTo(dest);
}

// The std::string will be similar to " 4, ENCRYPTED"
void PEM_ParseVersion(const std::string& proctype, std::string& version)
{
    size_t pos1 = 0;
    while (pos1 < proctype.size() && std::isspace(proctype[pos1])) pos1++;

    size_t pos2 = proctype.find(",");
    if (pos2 == std::string::npos)
        throw InvalidDataFormat("PEM_ParseVersion: failed to locate version");

    while (pos2 > pos1 && std::isspace(proctype[pos2])) pos2--;
    version = proctype.substr(pos1, pos2 - pos1);
}

// The std::string will be similar to " 4, ENCRYPTED"
void PEM_ParseOperation(const std::string& proctype, std::string& operation)
{
    size_t pos1 = proctype.find(",");
    if (pos1 == std::string::npos)
        throw InvalidDataFormat("PEM_ParseOperation: failed to locate operation");

    pos1++;
    while (pos1 < proctype.size() && std::isspace(proctype[pos1])) pos1++;

    operation = proctype.substr(pos1, std::string::npos);
    std::transform(operation.begin(), operation.end(), operation.begin(), (int(*)(int))std::toupper);
}

// The std::string will be similar to " AES-128-CBC, XXXXXXXXXXXXXXXX"
void PEM_ParseAlgorithm(const std::string& dekinfo, std::string& algorithm)
{
    size_t pos1 = 0;
    while (pos1 < dekinfo.size() && std::isspace(dekinfo[pos1])) pos1++;

    size_t pos2 = dekinfo.find(",");
    if (pos2 == std::string::npos)
        throw InvalidDataFormat("PEM_ParseVersion: failed to locate algorithm");

    while (pos2 > pos1 && std::isspace(dekinfo[pos2])) pos2--;

    algorithm = dekinfo.substr(pos1, pos2 - pos1);
    std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(),  (int(*)(int))std::toupper);
}

// The std::string will be similar to " AES-128-CBC, XXXXXXXXXXXXXXXX"
void PEM_ParseIV(const std::string& dekinfo, std::string& iv)
{
    size_t pos1 = dekinfo.find(",");
    if (pos1 == std::string::npos)
        throw InvalidDataFormat("PEM_ParseIV: failed to locate initialization vector");

    pos1++;
    while (pos1 < dekinfo.size() && std::isspace(dekinfo[pos1])) pos1++;

    iv = dekinfo.substr(pos1, std::string::npos);
    std::transform(iv.begin(), iv.end(), iv.begin(), (int(*)(int))std::toupper);
}

size_t PEM_ReadLine(BufferedTransformation& source, SecByteBlock& line, SecByteBlock& ending)
{
    if (!source.AnyRetrievable())
    {
        line.New(0);
        ending.New(0);

        return 0;
    }

    ByteQueue temp;
    while (source.AnyRetrievable())
    {
        byte b;
        if (!source.Get(b))
            throw Exception(Exception::OTHER_ERROR, "PEM_ReadLine: failed to read byte");

        // LF ?
        if (b == '\n')
        {
            ending = LF;
            break;
        }

        // CR ?
        if (b == '\r')
        {
            // CRLF ?
            if (source.AnyRetrievable() && source.Peek(b))
            {
                if (b == '\n')
                {
                    source.Skip(1);

                    ending = CRLF;
                    break;
                }
            }

            ending = CR;
            break;
        }

        // Not End-of-Line, accumulate it.
        temp.Put(b);
    }

    if (temp.AnyRetrievable())
    {
        line.Grow(temp.MaxRetrievable());
        temp.Get(line.data(), line.size());
    }
    else
    {
        line.New(0);
        ending.New(0);
    }

    // We return a line stripped of CRs and LFs. However, we return the actual number of
    //   of bytes processed, including the CR and LF. A return of 0 means nothing was read.
    //   A return of 1 means an empty line was read (CR or LF). A return of 2 could
    //   mean an empty line was read (CRLF), or could mean 1 character was read. In
    //   any case, line will hold whatever was parsed.
    return line.size() + ending.size();
}

inline void PEM_TrimLeadingWhitespace(BufferedTransformation& source)
{
    byte b;
    while (source.Peek(b) && std::isspace(b)) {
        source.Skip(1);
    }
}

NAMESPACE_END

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

NAMESPACE_BEGIN(CryptoPP)

using namespace CryptoPP::PEM;

PEM_Type PEM_GetType(const BufferedTransformation& bt)
{
    lword size = (std::min)(bt.MaxRetrievable(), lword(128));
    SecByteBlock temp(size);
    bt.Peek(temp, temp.size());
    return PEM_GetTypeFromBlock(temp);
}

bool PEM_NextObject(BufferedTransformation& src, BufferedTransformation& dest, bool trimTrailing)
{
    // Skip leading whitespace
    PEM_TrimLeadingWhitespace(src);

    // Anything to parse?
    if (!src.AnyRetrievable())
        return false;

    // We have four things to find:
    //   1. -----BEGIN (the leading begin)
    //   2. ----- (the trailing dashes)
    //   3. -----END (the leading end)
    //   4. ----- (the trailing dashes)

    // Once we parse something that purports to be PEM encoded, another routine
    //  will have to look for something particular, like a RSA key. We *will*
    //  inadvertently parse garbage, like -----BEGIN FOO BAR-----. It will
    //  be caught later when a PEM_Load routine is called.

    const size_t BAD_IDX = PEM_INVALID;

    // We use iterators for the search. However, an interator is invalidated
    //  after each insert that grows the container. So we save indexes
    //  from begin() to speed up searching. On each iteration, we simply
    //  reinitialize them.
    SecByteBlock::const_iterator it;
    size_t idx1 = BAD_IDX, idx2 = BAD_IDX, idx3 = BAD_IDX, idx4 = BAD_IDX;

    // The idea is to read chunks in case there are multiple keys or
    //  paramters in a BufferedTransformation. So we use CopyTo to
    //  extract what we are interested in. We don't take anything
    //  out of the BufferedTransformation (yet).

    // We also use indexes because the iterator will be invalidated
    //   when we append to the ByteQueue. Even though the iterator
    //   is invalid, `accum.begin() + index` will be valid.

    // Reading 8 or 10 lines at a time is an optimization from testing
    //   cacerts.pem. The file has 150 or so certs, so its a good test.
    // +2 to allow for CR + LF line endings. There's no guarantee a line
    //   will be present, or it will be PEM_LINE_BREAK in size.
    const size_t READ_SIZE = (PEM_LINE_BREAK + 1) * 10;
    const size_t REWIND_SIZE = (std::max)(PEM_BEGIN.size(), PEM_END.size()) + 2;

    SecByteBlock accum;
    size_t idx = 0, next = 0;

    size_t available = src.MaxRetrievable();
    while (available)
    {
        // How much can we read?
        const size_t size = (std::min)(available, READ_SIZE);

        // Ideally, we would only scan the line we are reading. However,
        //   we need to rewind a bit in case a token spans the previous
        //   block and the block we are reading. But we can't rewind
        //   into a previous index. Once we find an index, the variable
        //   next is set to it. Hence the reason for the std::max()
        if (idx > REWIND_SIZE)
        {
            const size_t x = idx - REWIND_SIZE;
            next = (std::max)(next, x);
        }

        // We need a temp queue to use CopyRangeTo. We have to use it
        //   because there's no Peek that allows us to peek a range.
        ByteQueue tq;
        src.CopyRangeTo(tq, static_cast<lword>(idx), static_cast<lword>(size));

        const size_t offset = accum.size();
        accum.Grow(offset + size);
        tq.Get(accum.data() + offset, size);

        // Adjust sizes
        idx += size;
        available -= size;

        // Locate '-----BEGIN'
        if (idx1 == BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), PEM_BEGIN.begin(), PEM_BEGIN.end());
            if (it == accum.end())
                continue;

            idx1 = it - accum.begin();
            next = idx1 + PEM_BEGIN.size();
        }

        // Locate '-----'
        if (idx2 == BAD_IDX && idx1 != BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), PEM_TAIL.begin(), PEM_TAIL.end());
            if (it == accum.end())
                continue;

            idx2 = it - accum.begin();
            next = idx2 + PEM_TAIL.size();
        }

        // Locate '-----END'
        if (idx3 == BAD_IDX && idx2 != BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), PEM_END.begin(), PEM_END.end());
            if (it == accum.end())
                continue;

            idx3 = it - accum.begin();
            next = idx3 + PEM_END.size();
        }

        // Locate '-----'
        if (idx4 == BAD_IDX && idx3 != BAD_IDX)
        {
            it = std::search(accum.begin() + next, accum.end(), PEM_TAIL.begin(), PEM_TAIL.end());
            if (it == accum.end())
                continue;

            idx4 = it - accum.begin();
            next = idx4 + PEM_TAIL.size();
        }
    }

    // Did we find `-----BEGIN XXX-----` (RFC 1421 calls this pre-encapsulated boundary)?
    if (idx1 == BAD_IDX || idx2 == BAD_IDX)
        throw InvalidDataFormat("PEM_NextObject: could not locate boundary header");

    // Did we find `-----END XXX-----` (RFC 1421 calls this post-encapsulated boundary)?
    if (idx3 == BAD_IDX || idx4 == BAD_IDX)
        throw InvalidDataFormat("PEM_NextObject: could not locate boundary footer");

    // *IF* the trailing '-----' occurred in the last 5 bytes in accum, then we might miss the
    // End of Line. We need to peek 2 more bytes if available and append them to accum.
    if (available >= 2)
    {
        ByteQueue tq;
        src.CopyRangeTo(tq, static_cast<lword>(idx), static_cast<lword>(2));

        const size_t offset = accum.size();
        accum.Grow(offset + 2);
        tq.Get(accum.data() + offset, 2);
    }
    else if (available == 1)
    {
        ByteQueue tq;
        src.CopyRangeTo(tq, static_cast<lword>(idx), static_cast<lword>(1));

        const size_t offset = accum.size();
        accum.Grow(offset + 1);
        tq.Get(accum.data() + offset, 1);
    }

    // Final book keeping
    const byte* ptr = accum.begin() + idx1;
    const size_t used = idx4 + PEM_TAIL.size();
    const size_t len = used - idx1;

    // Include one CR/LF if its available in the accumulator
    next = idx1 + len;
    size_t adjust = 0;
    if (next < accum.size())
    {
        byte c1 = accum[next];
        byte c2 = 0;

        if (next + 1 < accum.size())
            c2 = accum[next + 1];

        // Longest match first
        if (c1 == '\r' && c2 == '\n')
            adjust = 2;
        else if (c1 == '\r' || c1 == '\n')
            adjust = 1;
    }

    dest.Put(ptr, len + adjust);
    dest.MessageEnd();

    src.Skip(used + adjust);

    // Trailing whitespace of former queue is now
    // leading whitespace of the new queue.
    if (trimTrailing)
        PEM_TrimLeadingWhitespace(src);

    return true;
}

void PEM_Load(BufferedTransformation& bt, RSA::PublicKey& rsa)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, PUBLIC_BEGIN, PUBLIC_END);
    else if (type == PEM_RSA_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, RSA_PUBLIC_BEGIN, RSA_PUBLIC_END);
    else
        throw InvalidDataFormat("PEM_Load: not a RSA public key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPublicKey(temp, rsa, type == PEM_PUBLIC_KEY);
}

void PEM_Load(BufferedTransformation& bt, RSA::PrivateKey& rsa)
{
    return PEM_Load(bt, rsa, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, RSA::PrivateKey& rsa, const char* password, size_t length)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, PRIVATE_BEGIN, PRIVATE_END);
    else if (type == PEM_RSA_PRIVATE_KEY || (type == PEM_RSA_ENC_PRIVATE_KEY && password != NULL))
        PEM_StripEncapsulatedBoundary(obj, RSA_PRIVATE_BEGIN, RSA_PRIVATE_END);
    else if (type == PEM_RSA_ENC_PRIVATE_KEY && password == NULL)
        throw InvalidArgument("PEM_Load: RSA private key is encrypted");
    else
        throw InvalidDataFormat("PEM_Load: not a RSA private key");

    ByteQueue temp;
    if (type == PEM_RSA_ENC_PRIVATE_KEY)
        PEM_DecodeAndDecrypt(obj, temp, password, length);
    else
        PEM_Base64Decode(obj, temp);

    PEM_LoadPrivateKey(temp, rsa, type == PEM_PRIVATE_KEY);
}

void PEM_Load(BufferedTransformation& bt, DSA::PublicKey& dsa)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, PUBLIC_BEGIN, PUBLIC_END);
    else if (type == PEM_DSA_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, DSA_PUBLIC_BEGIN, DSA_PUBLIC_END);
    else
        throw InvalidDataFormat("PEM_Load: not a DSA public key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPublicKey(temp, dsa, type == PEM_PUBLIC_KEY);
}

void PEM_Load(BufferedTransformation& bt, DSA::PrivateKey& dsa)
{
    return PEM_Load(bt, dsa, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, DSA::PrivateKey& dsa, const char* password, size_t length)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, PRIVATE_BEGIN, PRIVATE_END);
    else if (type == PEM_DSA_PRIVATE_KEY || (type == PEM_DSA_ENC_PRIVATE_KEY && password != NULL))
        PEM_StripEncapsulatedBoundary(obj, DSA_PRIVATE_BEGIN, DSA_PRIVATE_END);
    else if (type == PEM_DSA_ENC_PRIVATE_KEY && password == NULL)
        throw InvalidArgument("PEM_Load: DSA private key is encrypted");
    else
        throw InvalidDataFormat("PEM_Load: not a DSA private key");

    ByteQueue temp;
    if (type == PEM_DSA_ENC_PRIVATE_KEY)
        PEM_DecodeAndDecrypt(obj, temp, password, length);
    else
        PEM_Base64Decode(obj, temp);

    PEM_LoadPrivateKey(temp, dsa);
}

void PEM_Load(BufferedTransformation& bt, ElGamal::PublicKey& key)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, PUBLIC_BEGIN, PUBLIC_END);
    else if (type == PEM_ELGAMAL_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, ELGAMAL_PUBLIC_BEGIN, ELGAMAL_PUBLIC_END);
    else
        throw InvalidDataFormat("PEM_Load: not a ElGamal public key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPublicKey(temp, key, type == PEM_PUBLIC_KEY);
}

void PEM_Load(BufferedTransformation& bt, ElGamal::PrivateKey& key)
{
    return PEM_Load(bt, key, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, ElGamal::PrivateKey& key, const char* password, size_t length)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, PRIVATE_BEGIN, PRIVATE_END);
    else if (type == PEM_ELGAMAL_PRIVATE_KEY || (type == PEM_ELGAMAL_ENC_PRIVATE_KEY && password != NULL))
        PEM_StripEncapsulatedBoundary(obj, ELGAMAL_PRIVATE_BEGIN, ELGAMAL_PRIVATE_END);
    else if (type == PEM_ELGAMAL_ENC_PRIVATE_KEY && password == NULL)
        throw InvalidArgument("PEM_Load: ElGamal private key is encrypted");
    else
        throw InvalidDataFormat("PEM_Load: not a ElGamal private key");

    ByteQueue temp;
    if (type == PEM_ELGAMAL_ENC_PRIVATE_KEY)
        PEM_DecodeAndDecrypt(obj, temp, password, length);
    else
        PEM_Base64Decode(obj, temp);

    PEM_LoadPrivateKey(temp, key, type == PEM_PRIVATE_KEY);
}

void PEM_Load(BufferedTransformation& bt, DL_GroupParameters_EC<ECP>& params)
{
    PEM_LoadParams(bt, params);
}

void PEM_Load(BufferedTransformation& bt, DL_GroupParameters_EC<EC2N>& params)
{
    PEM_LoadParams(bt, params);
}

void PEM_Load(BufferedTransformation& bt, DL_PublicKey_EC<ECP>& ec)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, PUBLIC_BEGIN, PUBLIC_END);
    else if (type == PEM_EC_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, EC_PUBLIC_BEGIN, EC_PUBLIC_END);
    else
        throw InvalidDataFormat("PEM_Load: not a public EC key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPublicKey(temp, ec, type == PEM_PUBLIC_KEY);
}

void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<ECP>& ec)
{
    return PEM_Load(bt, ec, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<ECP>& ec, const char* password, size_t length)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, PRIVATE_BEGIN, PRIVATE_END);
    else if (type == PEM_EC_PRIVATE_KEY || (type == PEM_EC_ENC_PRIVATE_KEY && password != NULL))
        PEM_StripEncapsulatedBoundary(obj, EC_PRIVATE_BEGIN, EC_PRIVATE_END);
    else if (type == PEM_EC_ENC_PRIVATE_KEY && password == NULL)
        throw InvalidArgument("PEM_Load: EC private key is encrypted");
    else
        throw InvalidDataFormat("PEM_Load: not a private EC key");

    ByteQueue temp;
    if (type == PEM_EC_ENC_PRIVATE_KEY)
        PEM_DecodeAndDecrypt(obj, temp, password, length);
    else
        PEM_Base64Decode(obj, temp);

    PEM_LoadPrivateKey(temp, ec, type == PEM_PRIVATE_KEY);
}

void PEM_Load(BufferedTransformation& bt, DL_PublicKey_EC<EC2N>& ec)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, PUBLIC_BEGIN, PUBLIC_END);
    else if (type == PEM_EC_PUBLIC_KEY)
        PEM_StripEncapsulatedBoundary(obj, EC_PUBLIC_BEGIN, EC_PUBLIC_END);
    else
        throw InvalidDataFormat("PEM_Load: not a public EC key");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    PEM_LoadPublicKey(temp, ec, type == PEM_PUBLIC_KEY);
}

void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<EC2N>& ec)
{
    return PEM_Load(bt, ec, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, DL_PrivateKey_EC<EC2N>& ec, const char* password, size_t length)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_PRIVATE_KEY)
        PEM_StripEncapsulatedBoundary(obj, PRIVATE_BEGIN, PRIVATE_END);
    else if (type == PEM_EC_PRIVATE_KEY || (type == PEM_EC_ENC_PRIVATE_KEY && password != NULL))
        PEM_StripEncapsulatedBoundary(obj, EC_PRIVATE_BEGIN, EC_PRIVATE_END);
    else if (type == PEM_EC_ENC_PRIVATE_KEY && password == NULL)
        throw InvalidArgument("PEM_Load: EC private key is encrypted");
    else
        throw InvalidDataFormat("PEM_Load: not a private EC key");

    ByteQueue temp;
    if (type == PEM_EC_ENC_PRIVATE_KEY)
        PEM_DecodeAndDecrypt(obj, temp, password, length);
    else
        PEM_Base64Decode(obj, temp);

    PEM_LoadPrivateKey(temp, ec, type == PEM_PRIVATE_KEY);
}

void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<ECP>::PrivateKey& ecdsa)
{
    return PEM_Load(bt, ecdsa, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<ECP>::PrivateKey& ecdsa, const char* password, size_t length)
{
    PEM_Load(bt, dynamic_cast<DL_PrivateKey_EC<ECP>&>(ecdsa), password, length);
}

void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<EC2N>::PrivateKey& ecdsa)
{
    return PEM_Load(bt, ecdsa, NULL, 0);
}

void PEM_Load(BufferedTransformation& bt, DL_Keys_ECDSA<EC2N>::PrivateKey& ecdsa, const char* password, size_t length)
{
    PEM_Load(bt, dynamic_cast<DL_PrivateKey_EC<EC2N>&>(ecdsa), password, length);
}

void PEM_Load(BufferedTransformation& bt, DL_GroupParameters_DSA& params)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_DSA_PARAMETERS)
        PEM_StripEncapsulatedBoundary(obj, DSA_PARAMETERS_BEGIN, DSA_PARAMETERS_END);
    else
        throw InvalidDataFormat("PEM_Read: invalid DSA parameters");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    params.Load(temp);
}

void PEM_Load(BufferedTransformation& bt, X509Certificate& cert)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    throw NotImplemented("PEM_Load: X.509 certificate is not implemented");
}

void PEM_DH_Load(BufferedTransformation& bt, Integer& p, Integer& g)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_DH_PARAMETERS)
        PEM_StripEncapsulatedBoundary(obj, DH_PARAMETERS_BEGIN, DH_PARAMETERS_END);
    else
        throw InvalidDataFormat("PEM_DH_Load: invalid DH parameters");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    BERSequenceDecoder dh(temp);
        p.BERDecode(dh);
        g.BERDecode(dh);
    dh.MessageEnd();

#if defined(PEM_KEY_OR_PARAMETER_VALIDATION) && !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if (!VerifyPrime(prng, p, 3))
        throw Exception(Exception::OTHER_ERROR, "PEM_DH_Load: p is not prime");

    // https://crypto.stackexchange.com/questions/12961/diffie-hellman-parameter-check-when-g-2-must-p-mod-24-11
    long residue = static_cast<long>(p.Modulo(24));
    if (residue != 11 && residue != 23)
        throw Exception(Exception::OTHER_ERROR, "PEM_DH_Load: g is not a suitable generator");
#endif
}

void PEM_DH_Load(BufferedTransformation& bt, Integer& p, Integer& q, Integer& g)
{
    ByteQueue obj;
    if (PEM_NextObject(bt, obj) == false)
        throw InvalidArgument("PEM_Load: PEM object not available");

    PEM_Type type = PEM_GetType(obj);
    if (type == PEM_DH_PARAMETERS)
        PEM_StripEncapsulatedBoundary(obj, DH_PARAMETERS_BEGIN, DH_PARAMETERS_END);
    else
        throw InvalidDataFormat("PEM_DH_Load: invalid DH parameters");

    ByteQueue temp;
    PEM_Base64Decode(obj, temp);

    BERSequenceDecoder dh(temp);
        p.BERDecode(dh);
        q.BERDecode(dh);
        g.BERDecode(dh);
    dh.MessageEnd();

#if defined(PEM_KEY_OR_PARAMETER_VALIDATION) && !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    if (!VerifyPrime(prng, p, 3))
        throw Exception(Exception::OTHER_ERROR, "PEM_DH_Load: p is not prime");

    // https://crypto.stackexchange.com/questions/12961/diffie-hellman-parameter-check-when-g-2-must-p-mod-24-11
    long residue = static_cast<long>(p.Modulo(24));
    if (residue != 11 && residue != 23)
        throw Exception(Exception::OTHER_ERROR, "PEM_DH_Load: g is not a suitable generator");
#endif
}

NAMESPACE_END
