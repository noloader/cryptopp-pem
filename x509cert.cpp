// x509cert.cpp - X.509 certificate read and write routines for Crypto++.
//                Written and placed in the public domain by Jeffrey Walton
//                and Geoff Beier

///////////////////////////////////////////////////////////////////////////
// For documentation on the X509Certificate class, see
//   http://www.cryptopp.com/wiki/X509Certificate and
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

#include "cryptlib.h"
#include "secblock.h"
#include "x509cert.h"
#include "integer.h"
#include "files.h"
#include "oids.h"
#include "trap.h"

#include "rsa.h"
#include "dsa.h"
#include "eccrypto.h"
#include "xed25519.h"

// For printing
#include "filters.h"
#include "hex.h"

// For Validate
#include "osrng.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

ANONYMOUS_NAMESPACE_BEGIN

using namespace CryptoPP;

class SecByteBlockSink : public Bufferless<Sink>
{
public:
    SecByteBlockSink(SecByteBlock &block) : m_block(block) { }

    size_t Put2(const byte *inString, size_t length, int, bool)
    {
        if(!inString || !length) return length;

        size_t currentSize = m_block.size();
        m_block.Grow(currentSize+length);
        std::memcpy(m_block+currentSize, inString, length);

        return 0;
    }

private:
    SecByteBlock& m_block;
};

bool HasOptionalAttribute(const BufferedTransformation &bt, byte tag)
{
    if (! bt.AnyRetrievable())
        return false;

    byte b;
    if (bt.Peek(b) && b == tag)
        return true;
    return false;
}

inline bool IsRSAAlgorithm(const OID& alg)
{
    return alg == ASN1::rsaEncryption() ||  // rsaEncryption is most popular in spki
        (alg >= ASN1::rsaEncryption() && alg <= ASN1::sha512_256WithRSAEncryption());
}

inline bool IsDSAAlgorithm(const OID& alg)
{
    return alg == ASN1::id_dsa();
}

inline bool IsEd25519Algorithm(const OID& alg)
{
    return alg == ASN1::Ed25519();
}

inline bool IsECPrimeFieldAlgorithm(const OID& alg, const OID& field)
{
    if (alg != ASN1::id_ecPublicKey())
        return false;

    return field == ASN1::prime_field() ||
        (field >= ASN1::secp112r1() && field <= ASN1::secp521r1()) ||
        (field >= ASN1::secp192r1() && field <= ASN1::secp256r1()) ||  // not a typo
        (field >= ASN1::brainpoolP160r1() && field <= ASN1::brainpoolP512r1());
}

inline bool IsECBinaryFieldAlgorithm(const OID& alg, const OID& field)
{
    if (alg != ASN1::id_ecPublicKey())
        return false;

    return field == ASN1::characteristic_two_field();
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

struct OidToName
{
    virtual ~OidToName() {};
    OidToName (const OID& o, const std::string& n) : oid(o), name(n) {}

    OID oid;
    std::string name;
};

std::string OidToNameLookup(const OID& oid, const char *defaultName)
{
    // Must be sorted by oid. The names are mostly standard.
    // Also see X.520, Section 6, for a partial list of LDAP Names.
    static const OidToName table[] =
    {
        { OID(0)+9+2342+19200300+100+1+ 1, "UID" },  // User Id
        { OID(0)+9+2342+19200300+100+1+25, "DC" },   // Domain component

        { OID(1)+2+840+10045+4+3+2, "ecdsaWithSHA256" },
        { OID(1)+2+840+10045+4+3+3, "ecdsaWithSHA384" },
        { OID(1)+2+840+10045+4+3+4, "ecdsaWithSHA512" },

        { OID(1)+2+840+113549+1+1+1, "rsaEncryption" },
        { OID(1)+2+840+113549+1+1+2, "md2WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+3, "md4WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+4, "md5WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+5, "sha1WithRSASignature" },
        { OID(1)+2+840+113549+1+1+6, "rsaOAEPEncryption" },
        { OID(1)+2+840+113549+1+1+7, "rsaAESOAEP" },
        { OID(1)+2+840+113549+1+1+10, "rsaSSAPSS" },
        { OID(1)+2+840+113549+1+1+11, "sha256WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+12, "sha384WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+13, "sha512WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+14, "sha224WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+15, "sha512-224WithRSAEncryption" },
        { OID(1)+2+840+113549+1+1+16, "sha512-256WithRSAEncryption" },

        { OID(1)+2+840+113549+1+9+1, "EMAIL" },  // Email address

        { OID(1)+3+6+1+4+1+311+20+2+3, "UPN" },  // Microsoft User Principal Name (UPN)
                                                 // Found in the SAN as [1] otherName

        { OID(2)+5+4+ 3,  "CN" },     // Common name
        { OID(2)+5+4+ 4,  "SN" },     // Surname
        { OID(2)+5+4+ 5,  "SERIALNUMBER" },  // Serial number
        { OID(2)+5+4+ 6,  "C" },      // Country
        { OID(2)+5+4+ 7,  "L" },      // Locality
        { OID(2)+5+4+ 8,  "ST" },     // State or province
        { OID(2)+5+4+ 9,  "STREET" }, // Street address
        { OID(2)+5+4+10,  "O" },      // Organization
        { OID(2)+5+4+11,  "OU" },     // Organization unit
        { OID(2)+5+4+12,  "TITLE" },  // Title
        { OID(2)+5+4+13,  "DESCRIPTION" },    // Description
        { OID(2)+5+4+16,  "POSTALADDRESS" },  // Postal address
        { OID(2)+5+4+17,  "POSTALCODE" },     // Postal code
        { OID(2)+5+4+18,  "POSTOFFICEBOX" },  // Postal office box
        { OID(2)+5+4+20,  "TEL" },    // Phone number
        { OID(2)+5+4+23,  "FAX" },    // Fax number
        { OID(2)+5+4+35,   "USERPASSWORD" },        // User password
        { OID(2)+5+4+35+2, "ENCUSERPASSWORD" },     // Encrypted user password
        { OID(2)+5+4+36,   "USERCERTIFICATE" },     // User certificate
        { OID(2)+5+4+36+2, "ENCUSERCERTIFICATE" },  // Encrypted user certificate
        { OID(2)+5+4+37,   "CACERTIFICATE" },       // CA certificate
        { OID(2)+5+4+37+2, "ENCCACERTIFICATE" },    // Encrypted CA certificate
        { OID(2)+5+4+41,  "NAME" },   // Name
        { OID(2)+5+4+42,  "GN" },     // Given name
        { OID(2)+5+4+43,  "I" },      // Initials
        { OID(2)+5+4+44,  "GENERATION" },  // Generation qualifier, Jr., Sr., etc
        { OID(2)+5+4+45,  "UID" },    // X.500 Unique identifier
        { OID(2)+5+4+49,  "DN" },     // Distinguished name
        { OID(2)+5+4+51,  "HOUSE" },  // House identifier
        { OID(2)+5+4+65,  "PSEUDONYM" },  // Pseudonym
        { OID(2)+5+4+78,  "OID" },      // Object identifier
        { OID(2)+5+4+83,  "URI" },      // Uniform Resource Identifier
        { OID(2)+5+4+85,  "USERPWD" },  // URI user password
        { OID(2)+5+4+86,  "URN" },      // Uniform Resource Name
        { OID(2)+5+4+87,  "URL" },      // Uniform Resource Locator

        { OID(2)+5+29+14, "SPKI" },   // Subject public key identifier
        { OID(2)+5+29+15, "KU" },     // Key usage
        { OID(2)+5+29+17, "SAN" },    // Subject alternate names
        { OID(2)+5+29+19, "BC" },     // Basic constraints
        { OID(2)+5+29+30, "NC" },     // Name constraints
        { OID(2)+5+29+35, "AKI" },    // Authority key identifier
        { OID(2)+5+29+37, "EKU" },    // Extended key usage

        { OID(2)+16+840+1+113730+1+12, "ssl-server-name" }, // Netscape server name
        { OID(2)+16+840+1+113730+1+13, "ns-comment" }       // Netscape comment
    };
    static const size_t elements = COUNTOF(table);

    // binary search
    size_t first  = 0;
    size_t last   = elements - 1;
    size_t middle = (first+last)/2;

    while (first <= last)
    {
        if (table[middle].oid < oid)
        {
            first = middle + 1;
        }
        else if (table[middle].oid == oid)
        {
            return table[middle].name;
        }
        else
            last = middle - 1;

        middle = (first + last)/2;
    }

    // Not found, return defaultName.
    if (defaultName != NULLPTR)
        return defaultName;

    std::ostringstream oss;
    oss << oid;
    return oss.str();
}

void RdnValue::BERDecode(BufferedTransformation &bt)
{
    BERSequenceDecoder seq(bt);

      m_oid.BERDecode(seq);

      byte b;
      if (seq.Peek(b) && ValidateTag(b))
      {
          m_tag = static_cast<ASNTag>(b);
          BERDecodeTextString(seq, m_value, b);
      }
      else
          BERDecodeError();

    seq.MessageEnd();
}

void RdnValue::DEREncode(BufferedTransformation &bt) const
{
    CRYPTOPP_UNUSED(bt);

    // TODO: Implement this function
    throw NotImplemented("RdnValue::DEREncode");
}

bool RdnValue::ValidateTag(byte tag) const
{
    if (tag == UTF8_STRING || tag == NUMERIC_STRING || tag == PRINTABLE_STRING ||
        tag == T61_STRING || tag == VIDEOTEXT_STRING || tag == IA5_STRING ||
        tag == VISIBLE_STRING || tag == GENERAL_STRING || tag == UNIVERSAL_STRING ||
        tag == BMP_STRING)
        return true;
    return false;
}

std::ostream& RdnValue::Print(std::ostream& out) const
{
    std::ostringstream oss;
    oss << OidToNameLookup(m_oid);
    oss << "=";
    oss << EncodeValue();

    return out << oss.str();
}

std::string RdnValue::EncodeValue() const
{
    if (m_value.empty())
        { return "\"\""; }

    bool quote = std::find(m_value.begin(), m_value.end(), byte(' ')) != m_value.end();

    std::string val;
    if (quote) val += "\"";
    val.append((const char*)ConstBytePtr(m_value), BytePtrSize(m_value));
    if (quote) val += "\"";

    return val;
}

void DateValue::BERDecode(BufferedTransformation &bt)
{
    byte b;
    if (bt.Peek(b) && ValidateTag(b))
    {
        m_tag = static_cast<ASNTag>(b);
        BERDecodeDate(bt, m_value, b);
    }
    else
        BERDecodeError();
}

void DateValue::DEREncode(BufferedTransformation &bt) const
{
    CRYPTOPP_UNUSED(bt);

    // TODO: Implement this function
    throw NotImplemented("DateValue::DEREncode");
}

bool DateValue::ValidateTag(byte tag) const
{
    if (tag == UTC_TIME || tag == GENERALIZED_TIME)
        return true;
    return false;
}

std::ostream& DateValue::Print(std::ostream& out) const
{
    if (m_value.empty())
        { return out; }

    return out << EncodeValue();
}

std::string DateValue::EncodeValue() const
{
    if (m_value.empty())
        { return ""; }

    return std::string((const char*)ConstBytePtr(m_value), BytePtrSize(m_value));
}

void ExtensionValue::BERDecode(BufferedTransformation &bt)
{
    BERSequenceDecoder seq(bt);
      m_oid.BERDecode(seq);

      m_critical = false;
      if (HasOptionalAttribute(seq, BOOLEAN))
      {
          BERGeneralDecoder flag(seq, BOOLEAN);
            byte b; flag.Get(b);
            m_critical = !!b;
          flag.MessageEnd();
      }

      BERDecodeOctetString(seq, m_value);

    seq.MessageEnd();
}

void ExtensionValue::DEREncode(BufferedTransformation &bt) const
{
    CRYPTOPP_UNUSED(bt);

    // TODO: Implement this function
    throw NotImplemented("ExtensionValue::DEREncode");
}

bool ExtensionValue::ValidateTag(byte tag) const
{
    return true;
}

std::ostream& ExtensionValue::Print(std::ostream& out) const
{
    if (m_value.empty())
        { return out; }

    return out << EncodeValue();
}

std::string ExtensionValue::EncodeValue() const
{
    // TODO: Implement this function
    throw NotImplemented("ExtensionValue::EncodeValue");
    return "";
}

void KeyIdentifierValue::BERDecode(BufferedTransformation &bt)
{
    byte tag;
    if (!bt.Peek(tag) || !ValidateTag(tag))
        BERDecodeError();

    if (tag == (CONSTRUCTED | SEQUENCE))
    {
        // Authority key identifier
        BERSequenceDecoder seq(bt);
          if (HasOptionalAttribute(seq, CONTEXT_SPECIFIC|0))
          {
              BERGeneralDecoder dec(seq, CONTEXT_SPECIFIC|0);
                SecByteBlockSink sink(m_value);
                dec.TransferTo(sink);
              dec.MessageEnd();
          }
        seq.MessageEnd();

        m_type = KeyIdentifierValue::Hash;
        m_oid = OID(2)+5+29+35;
    }
    else if (tag == OCTET_STRING)
    {
        // Subject key identifier
        BERDecodeOctetString(bt, m_value);
        m_type = KeyIdentifierValue::Hash;
        m_oid = OID(2)+5+29+14;
    }
    else
        BERDecodeError();
}

void KeyIdentifierValue::DEREncode(BufferedTransformation &bt) const
{
    CRYPTOPP_UNUSED(bt);

    // TODO: Implement this function
    throw NotImplemented("KeyIdentifierValue::DEREncode");
}

bool KeyIdentifierValue::ValidateTag(byte tag) const
{
    return (tag == (CONSTRUCTED | SEQUENCE)) || tag == OCTET_STRING;
}

std::ostream& KeyIdentifierValue::Print(std::ostream& out) const
{
    if (m_value.empty())
        { return out; }

    return out << EncodeValue();
}

std::string KeyIdentifierValue::EncodeValue() const
{
    std::string val;
    if (m_type == Hash)
    {
        val += "hash: ";

        HexEncoder encoder(new StringSink(val));
        encoder.Put(ConstBytePtr(m_value), BytePtrSize(m_value));
        encoder.MessageEnd();
    }
    else if (m_type == DnAndSn)
    {
        val += "name and serno: ";

        // TODO: finish this once we have a cert
        // val += "XXX, NNN";

        HexEncoder encoder(new StringSink(val));
        encoder.Put(ConstBytePtr(m_value), BytePtrSize(m_value));
        encoder.MessageEnd();
    }

    return val;
}

IdentityValue::IdentityValue(const SecByteBlock& value, IdentitySource src)
    : m_value(value), m_src(src)
{
    ConvertToText();
}

IdentityValue::IdentityValue(const std::string &value, IdentitySource src)
    : m_value(ConstBytePtr(value), BytePtrSize(value)), m_src(src)
{
    ConvertToText();
}

IdentityValue::IdentityValue(BufferedTransformation &value, IdentitySource src)
{
    SecByteBlockSink sink(m_value);
    value.TransferTo(sink);
    m_src = src;

    ConvertToText();
}

IdentityValue::IdentityValue(const OID &oid, BufferedTransformation &value, IdentitySource src)
{
    SecByteBlockSink sink(m_value);
    value.TransferTo(sink);
    m_oid = oid;
    m_src = src;

    ConvertToText();
}

IdentityValue::IdentityValue(const OID& oid, const SecByteBlock& value, IdentitySource src)
    : m_oid(oid), m_value(value), m_src(src)
{
    ConvertToText();
}

IdentityValue::IdentityValue(const OID& oid, const std::string &value, IdentitySource src)
    : m_oid(oid), m_value(ConstBytePtr(value), BytePtrSize(value)), m_src(src)
{
    ConvertToText();
}

void IdentityValue::ConvertToText()
{
    switch (m_src)
    {
        case UniqueId:
        case SubjectPKI:
        {
            HexEncoder encoder(new SecByteBlockSink(m_text));
            encoder.Put(ConstBytePtr(m_value), BytePtrSize(m_value));
            encoder.MessageEnd();
            break;
        }
        case iPAddress:
        {
            if (m_value.size() == 4)  // ipv4
            {
                std::ostringstream oss;
                for (size_t i=0; i<3; ++i)
                    oss << (unsigned int)m_value[i] << ".";
                oss << (unsigned int)m_value[3];
                const std::string& str = oss.str();
                m_text = SecByteBlock(ConstBytePtr(str), BytePtrSize(str));
            }
            else  // ipv6
            {
                HexEncoder encoder(new SecByteBlockSink(m_text), true, 2, ":");
                encoder.Put(ConstBytePtr(m_value), BytePtrSize(m_value));
                encoder.MessageEnd();
            }
            break;
        }
        default:
            m_text = m_value;
    }
}

std::ostream& IdentityValue::Print(std::ostream& out) const
{
    if (m_value.empty())
        { return out; }

    std::ostringstream oss;
    oss << OidToNameLookup(m_oid) << ": ";
    oss << EncodeValue();

    return out << oss.str();
}

std::string IdentityValue::EncodeValue() const
{
    if (m_text.empty())
        { return ""; }

    return std::string((const char*)ConstBytePtr(m_text), BytePtrSize(m_text));
}

void X509Certificate::Save(BufferedTransformation &bt) const
{
    DEREncode(bt);
}

void X509Certificate::Load(BufferedTransformation &bt)
{
    BERDecode(bt);
}

void X509Certificate::SaveCertificateBytes(BufferedTransformation &bt)
{
    m_origCertificate.resize(bt.MaxRetrievable());
    bt.Peek(m_origCertificate, m_origCertificate.size());
}

bool X509Certificate::HasOptionalAttribute(const BufferedTransformation &bt, byte tag) const
{
    byte b;
    if (bt.Peek(b) && b == tag)
        return true;
    return false;
}

const SecByteBlock& X509Certificate::GetToBeSigned() const
{
    if (m_toBeSigned.get() == NULLPTR)
    {
        m_toBeSigned.reset(new SecByteBlock);
        SecByteBlock &toBeSigned = *m_toBeSigned.get();

        ArraySource source(m_origCertificate, m_origCertificate.size(), true);
        SecByteBlockSink sink(toBeSigned);

        // The extra gyrations below are due to the ctor removing the tag and length
        BERSequenceDecoder cert(source);   // Certifcate octets, without tag and length
          BERSequenceDecoder tbs(cert);    // TBSCertifcate octets, without tag and length
            DERSequenceEncoder seq(sink);  // TBSCertifcate octets, with tag and length
              tbs.TransferTo(seq);         // Re-encoded TBSCertifcate, ready to verify
            seq.MessageEnd();
          tbs.MessageEnd();
        cert.SkipAll();
        cert.MessageEnd();
    }

    return *m_toBeSigned.get();
}

// RFC 5280, Appendix A, pp. 112-116
void X509Certificate::BERDecode(BufferedTransformation &bt)
{
    // Stash a copy of the certificate.
    SaveCertificateBytes(bt);

    BERSequenceDecoder certificate(bt);

      BERSequenceDecoder tbsCertificate(certificate);

        if (HasOptionalAttribute(tbsCertificate, CONTEXT_SPECIFIC|CONSTRUCTED|0))
            BERDecodeVersion(tbsCertificate, m_version);
        else
            m_version = v1;  // Default per RFC

        m_serialNumber.BERDecode(tbsCertificate);
        BERDecodeSignatureAlgorithm(tbsCertificate, m_subjectSignatureAlgortihm);

        BERDecodeDistinguishedName(tbsCertificate, m_issuerName);
        BERDecodeValidity(tbsCertificate, m_notBefore, m_notAfter);
        BERDecodeDistinguishedName(tbsCertificate, m_subjectName);

        BERDecodeSubjectPublicKeyInfo(tbsCertificate, m_subjectPublicKey);

        if (m_version < v2 || tbsCertificate.EndReached())
            goto TBS_Done;

        // UniqueIdentifiers are v2
        if (HasOptionalAttribute(tbsCertificate, CONTEXT_SPECIFIC|CONSTRUCTED|1))
            BERDecodeIssuerUniqueId(tbsCertificate);

        if (tbsCertificate.EndReached())
            goto TBS_Done;

        if (HasOptionalAttribute(tbsCertificate, CONTEXT_SPECIFIC|CONSTRUCTED|2))
            BERDecodeSubjectUniqueId(tbsCertificate);

        if (m_version < v3 || tbsCertificate.EndReached())
            goto TBS_Done;

        // Extensions are v3
        if (HasOptionalAttribute(tbsCertificate, CONTEXT_SPECIFIC|CONSTRUCTED|3))
            BERDecodeExtensions(tbsCertificate);

    TBS_Done:

      tbsCertificate.MessageEnd();

      BERDecodeSignatureAlgorithm(certificate, m_certSignatureAlgortihm);

      word32 unused;
      BERDecodeBitString(certificate, m_certSignature, unused);

    certificate.MessageEnd();
}

void X509Certificate::DEREncode(BufferedTransformation &bt) const
{
    CRYPTOPP_UNUSED(bt);

    // TODO: Implement this function
    throw NotImplemented("X509Certificate::DEREncode");
}

void X509Certificate::BERDecodeIssuerUniqueId(BufferedTransformation &bt)
{
    CRYPTOPP_ASSERT(HasOptionalAttribute(bt, CONTEXT_SPECIFIC|CONSTRUCTED|1));

    m_issuerUid.reset(new SecByteBlock);
    SecByteBlock temp;

    BERGeneralDecoder seq(bt, CONTEXT_SPECIFIC|CONSTRUCTED|1);
      word32 unused;
      BERDecodeBitString(bt, temp, unused);
    seq.MessageEnd();

    std::swap(temp, *m_issuerUid.get());
}

void X509Certificate::BERDecodeSubjectUniqueId(BufferedTransformation &bt)
{
    CRYPTOPP_ASSERT(HasOptionalAttribute(bt, CONTEXT_SPECIFIC|CONSTRUCTED|2));

    m_subjectUid.reset(new SecByteBlock);
    SecByteBlock temp;

    BERGeneralDecoder seq(bt, CONTEXT_SPECIFIC|CONSTRUCTED|2);
      word32 unused;
      BERDecodeBitString(bt, temp, unused);
    seq.MessageEnd();

    std::swap(temp, *m_subjectUid.get());
}

void X509Certificate::BERDecodeExtensions(BufferedTransformation &bt)
{
    CRYPTOPP_ASSERT(HasOptionalAttribute(bt, CONTEXT_SPECIFIC|CONSTRUCTED|3));

    m_extensions.reset(new ExtensionValueArray);
    ExtensionValueArray temp;

    BERGeneralDecoder extensions(bt, CONTEXT_SPECIFIC|CONSTRUCTED|3);

      BERSequenceDecoder seq(extensions);

        while (! seq.EndReached())
        {
            ExtensionValue value;
            value.BERDecode(seq);
            temp.push_back(value);
        }

      seq.MessageEnd();

    extensions.MessageEnd();

    std::swap(temp, *m_extensions.get());
}

void X509Certificate::BERDecodeSubjectPublicKeyInfo(BufferedTransformation &bt, member_ptr<X509PublicKey>& publicKey)
{
    OID algorithm;  // Public key algorithm
    OID field;      // Field for elliptic curves

    // See the comments for BERDecodeSubjectPublicKeyInfo for
    // why we are not using m_subjectSignatureAlgortihm.
    GetSubjectPublicKeyInfoOids(bt, algorithm, field);

    if (IsRSAAlgorithm(algorithm))
        publicKey.reset(new RSA::PublicKey);
    else if (IsDSAAlgorithm(algorithm))
        publicKey.reset(new DSA::PublicKey);
    else if (IsEd25519Algorithm(algorithm))
        publicKey.reset(new ed25519PublicKey);
    else if (IsECPrimeFieldAlgorithm(algorithm, field))
        publicKey.reset(new DL_PublicKey_EC<ECP>);
    else if (IsECBinaryFieldAlgorithm(algorithm, field))
        publicKey.reset(new DL_PublicKey_EC<EC2N>);
    else
    {
        std::ostringstream oss;
        oss << "X509Certificate::BERDecodeSubjectPublicKeyInfo: ";
        if (field.Empty() == false) {
            oss << "Field " << field << " is not supported";
        } else {
            oss << "Algorithm " << algorithm << " is not supported";
        }
        throw NotImplemented(oss.str());
    }

    publicKey->Load(bt);

#if defined(PEM_KEY_OR_PARAMETER_VALIDATION) && !defined(NO_OS_DEPENDENCE)
    AutoSeededRandomPool prng;
    publicKey->Validate(prng, 3);
#endif
}

// BERDecodeSubjectPublicKeyInfo peeks at the subjectPublicKeyInfo because the
// information is less ambiguous. If we used subjectPublicKeyAlgorithm we would
// still need to peek because subjectPublicKeyAlgorithm lacks field information
// (prime vs. binary). We need a field to instantiate a key. For example,
// subjectPublicKeyAlgorithm==ecdsa_with_sha384() does not contain enough
// information to determine PublicKey_EC<ECP> or PublicKey_EC<EC2N>.
void X509Certificate::GetSubjectPublicKeyInfoOids(BufferedTransformation &bt, OID& algorithm, OID& field) const
{
    try
    {
        // We need to read enough of the stream to determine the OIDs.
        ByteQueue temp;
        bt.CopyTo(temp, BERDecodePeekLength(bt));

        BERSequenceDecoder seq1(temp);
          BERSequenceDecoder seq2(seq1);
            algorithm.BERDecode(seq2);
            // EC Public Keys specify a field, also
            if (algorithm == ASN1::id_ecPublicKey())
                { field.BERDecode(seq2); }
            seq2.SkipAll();
          seq2.MessageEnd();
        seq1.SkipAll();
        seq1.MessageEnd();
    }
    catch (const Exception&)
    {
    }
}

void X509Certificate::BERDecodeValidity(BufferedTransformation &bt, DateValue &notBefore, DateValue &notAfter)
{
    BERSequenceDecoder validitiy(bt);
      notBefore.BERDecode(validitiy);
      notAfter.BERDecode(validitiy);
    validitiy.MessageEnd();
}

void X509Certificate::BERDecodeDistinguishedName(BufferedTransformation &bt, RdnValueArray &rdnArray)
{
    // The name is a RDNSequence. It looks like:
    //   SEQUENCE {
    //     SET {
    //       SEQUENCE {
    //         OBJECT IDENTIFIER countryName (2 5 4 6)
    //         PrintableString 'US'
    //       }
    //     }
    //     SET {
    //       SEQUENCE {
    //         OBJECT IDENTIFIER stateOrProvinceName (2 5 4 8)
    //         UTF8String 'NY'
    //       }
    //     }
    //     ...
    //   }

    RdnValueArray temp;
    BERSequenceDecoder rdnSequence(bt);

      while (! rdnSequence.EndReached())
      {
          BERSetDecoder set(rdnSequence);
            RdnValue value;
            value.BERDecode(set);
            temp.push_back(value);
          set.MessageEnd();
      }

    rdnSequence.MessageEnd();

    std::swap(temp, rdnArray);
}

void X509Certificate::BERDecodeSignatureAlgorithm(BufferedTransformation &bt, OID &algorithm)
{
    BERSequenceDecoder seq(bt);
      algorithm.BERDecode(seq);
      bool parametersPresent = seq.EndReached() ? false : BERDecodeAlgorithmParameters(seq);
      // TODO: Figure out what to do here???
      CRYPTOPP_ASSERT(parametersPresent == false);
      CRYPTOPP_UNUSED(parametersPresent);
    seq.MessageEnd();
}

void X509Certificate::BERDecodeVersion(BufferedTransformation &bt, Version &version)
{
    CRYPTOPP_ASSERT(HasOptionalAttribute(bt, CONTEXT_SPECIFIC|CONSTRUCTED|0));

    word32 value;

    BERGeneralDecoder ctx(bt, CONTEXT_SPECIFIC|CONSTRUCTED|0);
      BERDecodeUnsigned<word32>(ctx, value, INTEGER, 0, 2);  // check version
    ctx.MessageEnd();

    version = static_cast<Version>(value);
}

bool X509Certificate::Validate(RandomNumberGenerator &rng, unsigned int level) const
{
    // TODO: add more tests
    return m_subjectPublicKey->Validate(rng, level);
}

void X509Certificate::AssignFrom(const NameValuePairs &source)
{
    CRYPTOPP_UNUSED(source);

    // TODO: Implement this function
    throw NotImplemented("X509Certificate::AssignFrom");
}

bool X509Certificate::GetVoidValue(const char *name, const std::type_info &valueType, void *pValue) const
{
    CRYPTOPP_UNUSED(name); CRYPTOPP_UNUSED(valueType);
    CRYPTOPP_UNUSED(pValue);

    // TODO: Implement this function
    throw NotImplemented("X509Certificate::GetVoidValue");

    return false;
}

bool X509Certificate::FindExtension(const OID& oid, ExtensionValueArray::const_iterator& loc) const
{
    ExtensionValueArray::const_iterator first = m_extensions.get()->begin();
    ExtensionValueArray::const_iterator last = m_extensions.get()->end();

    while (first != last)
    {
        if (first->m_oid == oid) {
            loc = first;
            return true;
        }
        ++first;
    }
    loc = last;
    return false;
}

const KeyIdentifierValue& X509Certificate::GetAuthorityKeyIdentifier() const
{
    // OCTET STRING, encapsulates {
    //   SEQUENCE {
    //     [0]
    //       AE 22 75 36 0B F0 D2 37 CB D2 AB 5B 47 B7 9E B0
    //       ED 15 E5 9A
    //   }
    // }

    if (m_authorityKeyIdentifier.get() == NULLPTR)
    {
        m_authorityKeyIdentifier.reset(new KeyIdentifierValue);
        if (HasExtensions())
        {
            const OID keyIdentifier = OID(2)+5+29+35;
            ExtensionValueArray::const_iterator loc;

            if (FindExtension(keyIdentifier, loc))
            {
                const ExtensionValue& ext = *loc;
                KeyIdentifierValue& identifier = *m_authorityKeyIdentifier.get();

                ArraySource source(ext.m_value, ext.m_value.size(), true);
                identifier.BERDecode(source);
            }
        }
    }

    return *m_authorityKeyIdentifier.get();
}

const KeyIdentifierValue& X509Certificate::GetSubjectKeyIdentifier() const
{
    // OCTET STRING, encapsulates {
    //   OCTET STRING
    //     AE 22 75 36 0B F0 D2 37 CB D2 AB 5B 47 B7 9E B0
    //     ED 15 E5 9A
    //   }
    // }

    if (m_subjectKeyIdentifier.get() == NULLPTR)
    {
        m_subjectKeyIdentifier.reset(new KeyIdentifierValue);
        if (HasExtensions())
        {
            const OID keyIdentifier = OID(2)+5+29+14;
            ExtensionValueArray::const_iterator loc;

            if (FindExtension(keyIdentifier, loc))
            {
                const ExtensionValue& ext = *loc;
                KeyIdentifierValue& identifier = *m_subjectKeyIdentifier.get();

                ArraySource source(ext.m_value, ext.m_value.size(), true);
                identifier.BERDecode(source);
            }
        }
    }

    return *m_subjectKeyIdentifier.get();
}

void X509Certificate::GetIdentitiesFromSubjectUniqueId(IdentityValueArray& identityArray) const
{
    if (HasSubjectUniqueId())
    {
        IdentityValue identity(*m_subjectUid.get(), IdentityValue::UniqueId);
        identityArray.push_back(identity);
    }
}

void X509Certificate::GetIdentitiesFromSubjectPublicKeyId(IdentityValueArray& identityArray) const
{
    const OID spki = OID(2)+5+29+14;
    const KeyIdentifierValue& subjectKeyIdentifier = GetSubjectKeyIdentifier();
    IdentityValue identity(spki, subjectKeyIdentifier.m_value, IdentityValue::SubjectPKI);
    identityArray.push_back(identity);
}

void X509Certificate::GetIdentitiesFromSubjectDistName(IdentityValueArray& identityArray) const
{
    // The full readable string
    {
        std::ostringstream oss;
        oss << GetSubjectDistinguishedName();
        const std::string id(oss.str());

        const OID subjectDN = OID(2)+5+4+49;
        IdentityValue identity(subjectDN, id, IdentityValue::SubjectDN);
        identityArray.push_back(identity);
    }

    // Get the CommonName separately
    {
        const RdnValueArray& rdnArray = GetSubjectDistinguishedName();
        RdnValueArray::const_iterator first = rdnArray.begin();
        RdnValueArray::const_iterator last = rdnArray.end();

        const OID commonName = OID(2)+5+4+3;
        while (first != last)
        {
            if (first->m_oid == commonName)
            {
                IdentityValue identity(commonName, first->m_value, IdentityValue::SubjectCN);
                identityArray.push_back(identity);
                break;  // Only one common name
            }
            ++first;
        }
    }

    // Get the UniqueId separately
    {
        const RdnValueArray& rdnArray = GetSubjectDistinguishedName();
        RdnValueArray::const_iterator first = rdnArray.begin();
        RdnValueArray::const_iterator last = rdnArray.end();

        const OID uid = OID(2)+5+4+45;
        while (first != last)
        {
            if (first->m_oid == uid)
            {
                IdentityValue identity(uid, first->m_value, IdentityValue::SubjectUID);
                identityArray.push_back(identity);
                // Don't break due to multiple UniqueId's
            }
            ++first;
        }
    }

    // Get the PKCS#9 email separately
    {
        const RdnValueArray& rdnArray = GetSubjectDistinguishedName();
        RdnValueArray::const_iterator first = rdnArray.begin();
        RdnValueArray::const_iterator last = rdnArray.end();

        const OID email = OID(1)+2+840+113549+1+9+1;
        while (first != last)
        {
            if (first->m_oid == email)
            {
                IdentityValue identity(email, first->m_value, IdentityValue::SubjectEmail);
                identityArray.push_back(identity);
                // Don't break due to multiple emails
            }
            ++first;
        }
    }
}

void X509Certificate::GetIdentitiesFromSubjectAltName(IdentityValueArray& identityArray) const
{
    const OID subjectAltName = OID(2)+5+29+17;
    ExtensionValueArray::const_iterator loc;

    if (FindExtension(subjectAltName, loc))
    {
        const ExtensionValue& ext = *loc;
        ArraySource source(ext.m_value, ext.m_value.size(), true);

        BERSequenceDecoder seq(source);
          while (! seq.EndReached())
          {
              byte c;
              if (! seq.Get(c))
                  BERDecodeError();

              size_t l;
              if (! BERLengthDecode(seq, l))
                  BERDecodeError();

              SecByteBlock value(l);
              seq.Get(value, value.size());

              switch (c)
              {
                  case 0x80:
                  {
                    // Micosoft PKI can include a User Principal Name in the otherName
                    // https://security.stackexchange.com/q/62746/29925
                    CRYPTOPP_ASSERT(0);
                    break;
                  }
                  case 0x81:
                  {
                    IdentityValue identity(subjectAltName, value, IdentityValue::rfc822Name);
                    identityArray.push_back(identity);
                    break;
                  }
                  case 0x82:
                  {
                    IdentityValue identity(subjectAltName, value, IdentityValue::dNSName);
                    identityArray.push_back(identity);
                    break;
                  }
                  case 0x86:
                  {
                    IdentityValue identity(subjectAltName, value, IdentityValue::uniformResourceIdentifier);
                    identityArray.push_back(identity);
                    break;
                  }
                  case 0x87:
                  {
                    IdentityValue identity(subjectAltName, value, IdentityValue::iPAddress);
                    identityArray.push_back(identity);
                    break;
                  }
                  default:
                  {
                    // TODO: add other CHOICEs
                    CRYPTOPP_ASSERT(0);
                    seq.Skip(l);
                  }
              }
          }
        seq.MessageEnd();
    }
}

void X509Certificate::GetIdentitiesFromNetscapeServer(IdentityValueArray& identityArray) const
{
    const OID serverName = OID(2)+16+840+1+113730+1+12;
    ExtensionValueArray::const_iterator loc;

    if (FindExtension(serverName, loc))
    {
        const ExtensionValue& ext = *loc;
        ArraySource source(ext.m_value, ext.m_value.size(), true);

        BERSequenceDecoder seq(source);

          IdentityValue identity(serverName, seq, IdentityValue::nsServer);
          identityArray.push_back(identity);

        seq.MessageEnd();
    }
}

void X509Certificate::GetIdentitiesFromUserPrincipalName(IdentityValueArray& identityArray) const
{
    CRYPTOPP_UNUSED(identityArray);

    const OID upn = OID(1)+3+6+1+4+1+311+20+2+3;
    CRYPTOPP_UNUSED(upn);

    // TODO: finish this once we get a MS client cert
    // identity.m_src = IdentityValue::msOtherNameUPN;
}

const IdentityValueArray& X509Certificate::GetSubjectIdentities() const
{
    if (m_identities.get() == NULLPTR)
    {
        m_identities.reset(new IdentityValueArray);
        IdentityValueArray identities;

        GetIdentitiesFromSubjectUniqueId(identities);
        GetIdentitiesFromSubjectDistName(identities);
        GetIdentitiesFromSubjectPublicKeyId(identities);
        GetIdentitiesFromSubjectAltName(identities);
        GetIdentitiesFromNetscapeServer(identities);
        GetIdentitiesFromUserPrincipalName(identities);

        std::swap(*m_identities.get(), identities);
    }

    return *m_identities.get();
}

std::ostream& X509Certificate::Print(std::ostream& out) const
{
    std::ostringstream oss;
    std::ios_base::fmtflags base = out.flags() & std::ios_base::basefield;

    oss << "Version: " << GetVersion() << std::endl;
    oss << "Serial Number: " << "0x" << std::hex << GetSerialNumber() << std::endl;
    oss.setf(base, std::ios_base::basefield);  // reset basefield

    oss << "Not Before: " << GetNotBefore() << std::endl;
    oss << "Not After: " << GetNotAfter() << std::endl;

    oss << "Issuer DN: " << GetIssuerDistinguishedName() << std::endl;
    oss << "Subject DN: " << GetSubjectDistinguishedName() << std::endl;

    oss << "Authority KeyId: " << GetAuthorityKeyIdentifier() << std::endl;
    oss << "Subject KeyId: " << GetSubjectKeyIdentifier() << std::endl;

    // Format signature
    std::string signature;
    const SecByteBlock& binarySignature = GetCertificateSignature();
    StringSource(binarySignature, binarySignature.size(), true, new HexEncoder(new StringSink(signature)));
    signature.resize(60); signature += "...";

    // Format tbs
    std::string toBeSigned;
    const SecByteBlock& binaryToBeSigned = GetToBeSigned();
    StringSource(binaryToBeSigned, binaryToBeSigned.size(), true, new HexEncoder(new StringSink(toBeSigned)));
    toBeSigned.resize(60); toBeSigned += "...";

    const OID& algorithm = GetCertificateSignatureAlgorithm();
    oss << "Signature Alg: " << OidToNameLookup(algorithm) << std::endl;
    oss << "To Be Signed: " << toBeSigned << std::endl;
    oss << "Signature: " << signature;

    return out << oss.str();
}

void X509Certificate::WriteCertificateBytes(BufferedTransformation &bt) const
{
    try
    {
        bt.Put(m_origCertificate, m_origCertificate.size());
    }
    catch(const Exception&)
    {
    }
}

NAMESPACE_END  // Cryptopp
