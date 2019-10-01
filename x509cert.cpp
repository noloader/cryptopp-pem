// pem_common.cpp - commom PEM routines.
//                  Written and placed in the public domain by Jeffrey Walton

///////////////////////////////////////////////////////////////////////////
// For documentation on the PEM read and write routines, see
//   http://www.cryptopp.com/wiki/PEM_Pack
///////////////////////////////////////////////////////////////////////////

#include "cryptlib.h"
#include "secblock.h"
#include "x509cert.h"
#include "integer.h"
#include "oids.h"
#include "trap.h"

#include "rsa.h"
#include "dsa.h"
#include "eccrypto.h"
#include "xed25519.h"

// For printing
#include "filters.h"
#include "hex.h"

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

ANONYMOUS_NAMESPACE_BEGIN

using namespace CryptoPP;

struct OidToName
{
    OidToName (const OID& o, const std::string& n) : oid(o), name(n) {}

    OID oid;
    std::string name;
};

typedef std::vector<OidToName> OidToNameVector;

std::string OidToNameLookup(const OID& oid)
{
    // Must be sorted by oid. The names are mostly standard.
    static const OidToName table[] =
    {
        { OID(1)+2+840+113549+1+9+1, "EMAIL" },
        { OID(2)+5+4+ 3, "CN" },     // Common name
        { OID(2)+5+4+ 4, "SNAME" },  // Surname
        { OID(2)+5+4+ 5, "SERNO" },  // Serial number
        { OID(2)+5+4+ 6, "C" },      // Country
        { OID(2)+5+4+ 7, "L" },      // Locality
        { OID(2)+5+4+ 8, "ST" },     // State or province
        { OID(2)+5+4+ 9, "SADDR" },  // Street address
        { OID(2)+5+4+10, "O" },      // Organization
        { OID(2)+5+4+11, "OU" },     // Organization unit
        { OID(2)+5+4+12, "TITLE" },  // Title
        { OID(2)+5+4+13, "DESC" },   // Description
        { OID(2)+5+4+16, "PADDR" },  // Postal address
        { OID(2)+5+4+17, "ZIP" },    // Postal code
        { OID(2)+5+4+18, "POBOX" },  // Postal office box
        { OID(2)+5+4+20, "TEL" },    // Phone number
        { OID(2)+5+4+23, "FAX" },    // Fax number
        { OID(2)+5+4+35, "PASSWD" }, // User password
        { OID(2)+5+4+36, "EECERT" }, // User certificate
        { OID(2)+5+4+37, "CACERT" }, // CA certificate
        { OID(2)+5+4+41, "NAME" },   // Name
        { OID(2)+5+4+42, "GNAME" },  // Given name
        { OID(2)+5+4+45, "UID" },    // Unique identifier
        { OID(2)+5+4+49, "DN" },     // Distinguished name
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

    // Not found, return oid.
    std::ostringstream oss;
    oss << oid;
    return oss.str();
}

bool HasOptionalAttribute(const BufferedTransformation &bt, byte tag)
{
    if (! bt.AnyRetrievable())
        return false;

    byte b;
    if (bt.Peek(b) && b == tag)
        return true;
    return false;
}

ANONYMOUS_NAMESPACE_END

NAMESPACE_BEGIN(CryptoPP)

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
    if (tag == PRINTABLE_STRING || tag == IA5_STRING || tag == UTF8_STRING)
        return true;
    return false;
}

std::string RdnValue::EncodeRdnValue() const
{
    if (m_value.empty()) return "";

    std::string val; val.reserve(4+m_value.size());
    bool quote = std::find(m_value.begin(), m_value.end(), byte(' ')) != m_value.end();

    val = OidToNameLookup(m_oid);
    if (!val.empty()) val += "=";
    if (quote) val += "\"";
    val.append((const char*)m_value.data(), m_value.size());
    if (quote) val += "\"";

    return val;
}

std::ostream& RdnValue::Print(std::ostream& out) const
{
    if (m_value.empty()) return out;

    std::string val = EncodeRdnValue();
    return out.write(&val[0], val.size());
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
        return out;
    return out.write(reinterpret_cast<const char*>(&m_value[0]), m_value.size());
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
    // TODO: Implement this function
    throw NotImplemented("ExtensionValue::DEREncode");
    return out;
}

void X509Certificate::Save(BufferedTransformation &bt) const
{
    DEREncode(bt);
}

void X509Certificate::Load(BufferedTransformation &bt)
{
    // Stash a copy of the certificate.
    SaveCertificateBytes(bt);

    BERDecode(bt);
}

void X509Certificate::SaveCertificateBytes(BufferedTransformation &bt)
{
    m_origCertificate.resize(bt.MaxRetrievable());
    bt.Peek(m_origCertificate, m_origCertificate.size());
}

bool X509Certificate::HasOptionalAttribute(const BufferedTransformation &bt, byte tag) const
{
    if (! bt.AnyRetrievable())
        return false;

    byte b;
    if (bt.Peek(b) && b == tag)
        return true;
    return false;
}

const SecByteBlock& X509Certificate::GetToBeSigned() const
{
    if (m_toBeSigned.size() == 0)
    {
        ArraySource source(m_origCertificate, m_origCertificate.size(), true);
        m_toBeSigned.resize(m_origCertificate.size());
        ArraySink sink(m_toBeSigned, m_toBeSigned.size());

        BERSequenceDecoder seq(source);
          seq.TransferTo(sink, m_toBeSigned.size());
        seq.MessageEnd();
    }

    return m_toBeSigned;
}

/*
   RFC 5280, Appendix A, pp. 112-116

   Certificate  ::=  SEQUENCE  {
     tbsCertificate       TBSCertificate,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING  }

   TBSCertificate  ::=  SEQUENCE  {
     version         [0]  Version DEFAULT v1,
     serialNumber         CertificateSerialNumber,
     signature            AlgorithmIdentifier,
     issuer               Name,
     validity             Validity,
     subject              Name,
     subjectPublicKeyInfo SubjectPublicKeyInfo,
     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                          -- If present, version MUST be v2 or v3
     extensions      [3]  Extensions OPTIONAL
                          -- If present, version MUST be v3 --  }

   AlgorithmIdentifier  ::=  SEQUENCE  {
     algorithm               OBJECT IDENTIFIER,
     parameters              ANY DEFINED BY algorithm OPTIONAL  }

   Name ::= CHOICE { -- only one possibility for now --
      rdnSequence  RDNSequence }

   RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

   DistinguishedName ::=   RDNSequence

   RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

   AttributeType           ::= OBJECT IDENTIFIER

   AttributeValue          ::= ANY -- DEFINED BY AttributeType

   AttributeTypeAndValue   ::= SEQUENCE {
        type    AttributeType,
        value   AttributeValue  }

   Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

   Extension  ::=  SEQUENCE  {
     extnID      OBJECT IDENTIFIER,
     critical    BOOLEAN DEFAULT FALSE,
     extnValue   OCTET STRING
                 -- contains the DER encoding of an ASN.1 value
                 -- corresponding to the extension type identified
                 -- by extnID  }
*/

void X509Certificate::BERDecode(BufferedTransformation &bt)
{
    BERSequenceDecoder certificate(bt);

      BERSequenceDecoder tbsCertificate(certificate);

        if (HasOptionalAttribute(tbsCertificate, CONTEXT_SPECIFIC|CONSTRUCTED|0))
            BERDecodeVersion(tbsCertificate, m_version);
        else
            m_version = v1;  // Default per RFC

        m_serialNumber.BERDecode(tbsCertificate);
        BERDecodeSignatureAlgorithm(tbsCertificate, m_certSignatureAlgortihm);

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

    GetSubjectPublicKeyInfoOids(bt, algorithm, field);

    if (algorithm == ASN1::rsaEncryption())
        publicKey.reset(new RSA::PublicKey);
    else if (algorithm == ASN1::id_dsa())
        publicKey.reset(new DSA::PublicKey);
    else if (algorithm == ASN1::id_ecPublicKey() && field == ASN1::prime_field())
        publicKey.reset(new DL_PublicKey_EC<ECP>);
    else if (algorithm == ASN1::id_ecPublicKey() && field == ASN1::characteristic_two_field())
        publicKey.reset(new DL_PublicKey_EC<EC2N>);
    else if (algorithm == ASN1::Ed25519())
        publicKey.reset(new ed25519PublicKey);
    else
    {
        std::ostringstream oss;
        oss << algorithm << " is not supported at the moment";
        throw NotImplemented(oss.str());
    }

    publicKey->Load(bt);
}

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
                field.BERDecode(seq2);
            seq2.SkipAll();
          seq2.MessageEnd();
        seq1.MessageEnd();
    }
    catch (const Exception&)
    {
    }
}

void X509Certificate::BERDecodeValidity(BufferedTransformation &bt, DateValue &notBefore, DateValue &notAfter)
{
    BERSequenceDecoder validitiy(bt);
      BERDecodeDate(validitiy, notBefore);
      BERDecodeDate(validitiy, notAfter);
    validitiy.MessageEnd();
}

void X509Certificate::BERDecodeDate(BufferedTransformation &bt, DateValue &date)
{
    date.BERDecode(bt);
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
    CRYPTOPP_UNUSED(rng); CRYPTOPP_UNUSED(level);

    // TODO: Implement this function
    throw NotImplemented("X509Certificate::Validate");

    return false;
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

    oss << "Signature Alg: " << GetCertificateSignatureAlgorithm() << std::endl;
    oss << "To Be Signed: " << toBeSigned << std::endl;
    oss << "Signature: " << signature;

    // No endl for the last entry. Caller is responsible to add it.

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
