// x509cert.h - X.509 certificate read and write routines for Crypto++.
//              Written and placed in the public domain by Jeffrey Walton
//              and Geoff Beier

/// \file x509cert.h
/// \brief Classes and functions to read X.509 certificates
/// \details X509Certificate is a partial implementation of X.509 certificate
///  parsing. The class loads a DER encoded certificate and presents many of
///  the more important attributes and values through accessor functions. The
///  attributes and values include signature, signature algorithm, toBeSigned,
///  and subjectPublicKeyInfo exposed as a X509PubliKey ready for use in
///  Crypto++ library algorithms.
/// \details This is a library add-on. You must download and compile it
///  yourself.
/// \since Crypto++ 8.3
/// \sa <A HREF="http://www.cryptopp.com/wiki/X509Certificate">X509Certificate</A>
///  and <A HREF="http://www.cryptopp.com/wiki/PEM_Pack">PEM Pack</A> on the
///  Crypto++ wiki.

/////////////////////////////////////////////////////////////////////////////

#ifndef CRYPTOPP_X509_CERTIFICATE_H
#define CRYPTOPP_X509_CERTIFICATE_H

#include "cryptlib.h"
#include "secblock.h"
#include "stdcpp.h"
#include "asn.h"

#include <iosfwd>
#include <string>
#include <vector>
#include <sstream>

NAMESPACE_BEGIN(CryptoPP)

// Forward declaration
class Integer;

/// \brief Convert OID to a LDAP name
/// \param oid the object identifier
/// \param defaultName the name to use if lookup fails
/// \returns the LDAP name for display
/// \details LDAP names are specified in ITU X.520 and other places, like the RFCs.
///  If defaultName is NULL, then the OID is used.
std::string OidToNameLookup(const OID& oid, const char *defaultName=NULLPTR);

/// \brief ASNTag initializer
/// \details 0 is an invalid tag value
const ASNTag InvalidTag = static_cast<ASNTag>(0);

/// \brief X.500 Relative Distinguished Name value
struct RdnValue : public ASN1Object
{
    virtual ~RdnValue() {}
    RdnValue() : m_tag(InvalidTag) {}

    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const;

    bool ValidateTag(byte tag) const;

    /// \brief Print an RDN value
    /// \returns ostream reference
    std::ostream& Print(std::ostream& out) const;

    /// \brief Textual representation
    /// \returns string representing the value
    std::string EncodeValue() const;

    OID m_oid;
    SecByteBlock m_value;
    ASNTag m_tag;
};

/// \brief Array of Relative Distinguished Name values
typedef std::vector<RdnValue> RdnValueArray;

/// \brief X.690 Date value
struct DateValue : public ASN1Object
{
    DateValue() : m_tag(InvalidTag) {}
    virtual ~DateValue() {}

    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const;

    bool ValidateTag(byte tag) const;

    /// \brief Print a Date value
    /// \returns ostream reference
    std::ostream& Print(std::ostream& out) const;

    /// \brief Textual representation
    /// \returns string representing the value
    std::string EncodeValue() const;

    SecByteBlock m_value;
    ASNTag m_tag;
};

/// \brief X.509 Extension value
struct ExtensionValue : public ASN1Object
{
    virtual ~ExtensionValue() {}
    ExtensionValue() : m_tag(InvalidTag) {}

    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const;

    bool ValidateTag(byte tag) const;

    /// \brief Print an Extension value
    /// \returns ostream reference
    std::ostream& Print(std::ostream& out) const;

    /// \brief Textual representation
    /// \returns string representing the value
    std::string EncodeValue() const;

    OID m_oid;
    SecByteBlock m_value;
    ASNTag m_tag;
    bool m_critical;
};

/// \brief Array of X.509 Extension values
typedef std::vector<ExtensionValue> ExtensionValueArray;

/// \brief X.509 KeyIdentifier value
struct KeyIdentifierValue : public ASN1Object
{
    enum KeyIdentifierType {
        /// \brief Hash of the public key
        Hash=1,
        /// \brief Distinguised name and serial number
        DnAndSn
    };
    /// \brief Invalid identifier
    const KeyIdentifierType InvalidKeyIdentifier = static_cast<KeyIdentifierType>(0);

    virtual ~KeyIdentifierValue() {}
    KeyIdentifierValue() : m_type(InvalidKeyIdentifier) {}

    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const;

    bool ValidateTag(byte tag) const;

    /// \brief Print an Extension value
    /// \returns ostream reference
    std::ostream& Print(std::ostream& out) const;

    /// \brief Textual representation
    /// \returns string representing the value
    std::string EncodeValue() const;

    OID m_oid;
    SecByteBlock m_value;
    KeyIdentifierType m_type;
};

/// \brief Identity value
/// \details IdentityValue holds an identity and provides a textual representation of it.
struct IdentityValue
{
    enum IdentitySource {
        UniqueId=1, SubjectDN, SubjectCN, SubjectUID, SubjectEmail, SubjectPKI,
        otherName, rfc822Name, dNSName, x400Address, directoryName,        // SAN
        ediPartyName, uniformResourceIdentifier, iPAddress, registeredID,  // SAN
        nsServer, msOtherNameUPN
    };
    const IdentitySource InvalidIdentitySource = static_cast<IdentitySource>(0);

    virtual ~IdentityValue() {}
    IdentityValue() : m_src(InvalidIdentitySource) {}
    IdentityValue(const SecByteBlock &value, IdentitySource src);
    IdentityValue(const std::string &value, IdentitySource src);
    IdentityValue(const OID &oid, const SecByteBlock &value, IdentitySource src);
    IdentityValue(const OID &oid, const std::string &value, IdentitySource src);

    /// \brief Print an Identity value
    /// \returns ostream reference
    std::ostream& Print(std::ostream& out) const;

    /// \brief Textual representation
    /// \returns string representing the value
    std::string EncodeValue() const;

    /// \brief Convert this otherName into a different IdentityValue
    void ConvertOtherName();

    OID m_oid;
    SecByteBlock m_value;  // Raw value from source
    IdentitySource m_src;
};

typedef std::vector<IdentityValue> IdentityValueArray;

/// \brief X.509 Certificate
/// \details X509Certificate is a partial implementation of X.509 certificate
///  support. The class loads a DER encoded certificate and presents many of
///  the important attributes and values through accessor functions. The
///  attributes and values include signature, signature algorithm, toBeSigned,
///  serialNumber, issuerDistinguishedName, subjectDistinguishedName, and
///  subjectPublicKeyInfo exposed as a X509PubliKey ready for use in Crypto++
///  library algorithms.
/// \details Most member functions related to saving or encoding a certifcate
///  have not been cut-in. Calling member functions that have not been cut-in will
///  result in NotImplemented exception. Future versions of the X509Certificate
///  can provide them.
/// \throws NotImplemented if a particular function has not been cut-in. Member
///  functions that will throw NotImplemented include Save, AssignFrom,
///  GetVoidValue, and Validate.
/// \details This is a library add-on. You must download and compile it
///  yourself.
/// \since Crypto++ 8.3
/// \sa <A HREF="http://www.cryptopp.com/wiki/X509Certificate">X509Certificate</A>
///  and <A HREF="http://www.cryptopp.com/wiki/PEM_Pack">PEM Pack</A> on the
///  Crypto++ wiki.
class X509Certificate : public ASN1CryptoMaterial<Certificate>
{
public:

    /// \brief Certificate version
    enum Version {
        /// \brief Version 1
        v1=0,
        /// \brief Version 2
        v2,
        /// \brief Version 3
        v3
    };

public:
    virtual ~X509Certificate() {}
    X509Certificate() {}

    // CryptoMaterial
    virtual bool Validate (RandomNumberGenerator &rng, unsigned int level) const;

    // ASN1CryptoMaterial
    virtual void Save (BufferedTransformation &bt) const;
    virtual void Load (BufferedTransformation &bt);

    // NameValuePairs
    virtual void AssignFrom (const NameValuePairs &source);
    virtual bool GetVoidValue (const char *name, const std::type_info &valueType, void *pValue) const;

    // ASN1Object
    virtual void BERDecode (BufferedTransformation &bt);
    virtual void DEREncode (BufferedTransformation &bt) const;

    /// \brief Decode algorithm parameters
    /// \param bt BufferedTransformation object
    /// \sa BERDecodePublicKey, <A HREF="http://www.ietf.org/rfc/rfc2459.txt">RFC
    ///  2459, section 7.3.1</A>
    virtual bool BERDecodeAlgorithmParameters (BufferedTransformation &bt)
        {BERDecodeNull(bt); return false;}

    /// \brief Encode algorithm parameters
    /// \param bt BufferedTransformation object
    /// \sa DEREncodePublicKey, <A HREF="http://www.ietf.org/rfc/rfc2459.txt">RFC
    ///  2459, section 7.3.1</A>
    virtual bool DEREncodeAlgorithmParameters (BufferedTransformation &bt) const
        {DEREncodeNull(bt); return false;}

    /// \brief Retrieve complete DER encoded certicate
    /// \returns the certificate data
    /// \sa GetToBeSigned
    const SecByteBlock& GetCertificate () const
        { return m_origCertificate; }

    /// \brief Retrieve DER encoded ToBeSigned
    /// \returns the toBeSigned data
    /// \sa GetCertificate
    const SecByteBlock& GetToBeSigned () const;

    /// \brief Version number
    /// \returns Certificate version number
    /// \note Version number is 0 based, so X.509 v3 value is 2.
    Version GetVersion() const
        { return m_version; }

    /// \brief Serial number
    /// \returns Certificate serial number
    const Integer& GetSerialNumber() const
        { return m_serialNumber; }

    /// \brief Certificate signature algorithm
    /// \returns Certificate signature algorithm
    /// \sa GetCertificateSignature
    const OID& GetCertificateSignatureAlgorithm() const
        { return m_certSignatureAlgortihm; }

    /// \brief Certificate signature
    /// \returns Certificate signature
    /// \sa GetCertificateSignatureAlgorithm
    const SecByteBlock& GetCertificateSignature() const
        { return m_certSignature; }

    /// \brief Validity not before
    /// \returns Validity not before
    /// \sa GetNotAfter
    const DateValue& GetNotBefore() const
        { return m_notBefore; }

    /// \brief Validity not after
    /// \returns Validity not after
    /// \sa GetNotBefore
    const DateValue& GetNotAfter() const
        { return m_notAfter; }

    /// \brief Issuer distinguished name
    /// \returns Issuer distinguished name
    const RdnValueArray& GetIssuerDistinguishedName() const
        { return m_issuerName; }

    /// \brief Subject distinguished name
    /// \returns Subject distinguished name
    const RdnValueArray& GetSubjectDistinguishedName() const
        { return m_subjectName; }

    /// \brief Issuer UniqueId
    /// \returns Issuer UniqueId
    /// \details Issuer UniqueId is optional and available with X.509 v2.
    /// \sa HasIssuerUniqueId
    const SecByteBlock& GetIssuerUniqueId() const
        { return *m_issuerUid.get(); }

    /// \brief Subject UniqueId
    /// \returns Subject UniqueId
    /// \details Subject UniqueId is optional and available with X.509 v2.
    /// \sa HasSubjectUniqueId
    const SecByteBlock& GetSubjectUniqueId() const
        { return *m_subjectUid.get(); }

    /// \brief Certificate extensions
    /// \returns Certificate extensions array
    /// \details Certificate extensions are available with X.509 v3.
    /// \sa HasExtensions
    const ExtensionValueArray& GetExtensions() const
        { return *m_extensions.get(); }

    /// \brief Subject public key algorithm
    /// \returns Subject public key algorithm
    /// \sa GetSubjectPublicKey
    const OID& GetSubjectPublicKeyAlgorithm() const
        { return m_subjectSignatureAlgortihm; }

    /// \brief Subject public key
    /// \returns Subject public key
    /// \sa GetSubjectPublicKeyAlgorithm
    const X509PublicKey& GetSubjectPublicKey() const
        { return *m_subjectPublicKey.get(); }

    /// \brief Determine if Issuer UniqueId is present
    /// \returns true if Issuer UniqueId is present, false otherwise
    /// \details Issuer UniqueId is optional and available with X.509 v2.
    /// \sa HasSubjectUniqueId, GetIssuerUniqueId
    bool HasIssuerUniqueId() const
        { return m_issuerUid.get() != NULLPTR; }

    /// \brief Determine if Subject UniqueId is present
    /// \returns true if Subject UniqueId is present, false otherwise
    /// \details Subject UniqueId is optional and available with X.509 v2.
    /// \sa HasIssuerUniqueId, GetSubjectUniqueId
    bool HasSubjectUniqueId() const
        { return m_subjectUid.get() != NULLPTR; }

    /// \brief Determine if Extensions are present
    /// \returns true if Extensions are present, false otherwise
    /// \details Extensions are optional and available with X.509 v3.
    /// \sa GetExtensions
    bool HasExtensions() const
        { return m_extensions.get() != NULLPTR; }

    /// \brief Authority key identifier
    /// \returns Authority key identifier
    /// \details Authority key identifier is optional and available with X.509 v3.
    /// \sa GetSubjectKeyIdentifier
    const KeyIdentifierValue& GetAuthorityKeyIdentifier() const;

    /// \brief Subject key identifier
    /// \returns Subject key identifier
    /// \details Subject key identifier is optional and available with X.509 v3.
    /// \sa GetAuthorityKeyIdentifier
    const KeyIdentifierValue& GetSubjectKeyIdentifier() const;

    /// \brief Identities
    /// \returns Identities
    /// \details GetSubjectIdentities() attempts to collect the identities in the certificate.
    const IdentityValueArray& GetSubjectIdentities() const;

    /// \brief Print a certificate
    /// \param out ostream object
    /// \returns ostream reference
    /// \details Print() displays some of the fields of a certificate for
    ///  debug purposes. Users should modify the class or override this
    ///  class in a derived class to suit their taste.
    virtual std::ostream& Print(std::ostream& out) const;

    /// \brief Write certificate data
    /// \param bt BufferedTransformation object
    /// \details WriteCertificateBytes() is a debug function. It dumps
    ///  the bytes stored in m_origCertificate. WriteCertificateBytes()
    ///  also sets up a try/catch and silently swallows exceptions.
    void WriteCertificateBytes(BufferedTransformation &bt) const;

protected:
    // Crib away the original certificate
    void SaveCertificateBytes(BufferedTransformation &bt);

    void BERDecodeVersion(BufferedTransformation &bt, Version &version);
    void BERDecodeSignatureAlgorithm(BufferedTransformation &bt, OID &algorithm);
    void BERDecodeDistinguishedName(BufferedTransformation &bt, RdnValueArray &rdnArray);
    void BERDecodeValidity(BufferedTransformation &bt, DateValue &notBefore, DateValue &notAfter);
    void BERDecodeSubjectPublicKeyInfo(BufferedTransformation &bt, member_ptr<X509PublicKey>& publicKey);

    // Optional attributes
    bool HasOptionalAttribute(const BufferedTransformation &bt, byte tag) const;
    void BERDecodeIssuerUniqueId(BufferedTransformation &bt);
    void BERDecodeSubjectUniqueId(BufferedTransformation &bt);
    void BERDecodeExtensions(BufferedTransformation &bt);

    // BERDecodeSubjectPublicKeyInfo peeks at the subjectPublicKeyInfo because the
    // information is less ambiguous. If we used subjectPublicKeyAlgorithm we would
    // still need to peek because subjectPublicKeyAlgorithm lacks field information
    // (prime vs. binary). We need a field to instantiate a key. For example,
    // subjectPublicKeyAlgorithm==ecdsa_with_sha384() does not contain enough
    // information to determine PublicKey_EC<ECP> or PublicKey_EC<EC2N>.
    void GetSubjectPublicKeyInfoOids(BufferedTransformation &bt, OID& algorithm, OID& field) const;

    // Identity helper functions. Find them wherever we can.
    void GetIdentitiesFromSubjectDistName(IdentityValueArray& identityArray) const;
    void GetIdentitiesFromSubjectAltName(IdentityValueArray& identityArray) const;
    void GetIdentitiesFromSubjectUniqueId(IdentityValueArray& identityArray) const;
    void GetIdentitiesFromSubjectPublicKeyId(IdentityValueArray& identityArray) const;
    void GetIdentitiesFromNetscapeServer(IdentityValueArray& identityArray) const;
    void GetIdentitiesFromUserPrincipalName(IdentityValueArray& identityArray) const;

    // Find an extension with the OID. Returns false and end() if not found.
    bool FindExtension(const OID& oid, ExtensionValueArray::const_iterator& loc) const;

private:
    Version m_version;
    Integer m_serialNumber;

    // certificate algorithm and signature
    OID m_certSignatureAlgortihm;
    SecByteBlock m_certSignature;

    RdnValueArray m_issuerName;
    RdnValueArray m_subjectName;

    DateValue m_notBefore, m_notAfter;

    // The subject's key and algorithm
    OID m_subjectSignatureAlgortihm;
    member_ptr<X509PublicKey> m_subjectPublicKey;

    // Certificate v2, optional
    ASNOptional<SecByteBlock> m_issuerUid;
    ASNOptional<SecByteBlock> m_subjectUid;

    // Certificate v3, optional
    ASNOptional<ExtensionValueArray> m_extensions;

    // SKI and AKI extensions
    mutable member_ptr<KeyIdentifierValue> m_subjectKeyIdentifier;    // lazy
    mutable member_ptr<KeyIdentifierValue> m_authorityKeyIdentifier;  // lazy

    // Identities
    mutable member_ptr<IdentityValueArray> m_identities;  // lazy

    // Hack so we can examine the octets and verify the signature
    SecByteBlock m_origCertificate;
    mutable member_ptr<SecByteBlock> m_toBeSigned;  // lazy
};

inline std::ostream& operator<<(std::ostream& out, const X509Certificate &cert)
    { return cert.Print(out); }
inline std::ostream& operator<<(std::ostream& out, const RdnValue &value)
    { return value.Print(out); }
inline std::ostream& operator<<(std::ostream& out, const DateValue &value)
    { return value.Print(out); }
inline std::ostream& operator<<(std::ostream& out, const KeyIdentifierValue &value)
    { return value.Print(out); }
inline std::ostream& operator<<(std::ostream& out, const IdentityValue &value)
    { return value.Print(out); }

inline std::ostream& operator<<(std::ostream& out, const RdnValueArray &values)
{
    RdnValueArray::const_iterator beg = values.begin();
    RdnValueArray::const_iterator end = values.end();
    std::ostringstream oss;

    while (beg != end)
    {
        oss << *beg;
        if (++beg != end)
            { oss << "; "; }
    }
    return out << oss.str();
}

inline std::ostream& operator<<(std::ostream& out, const IdentityValueArray &values)
{
    IdentityValueArray::const_iterator beg = values.begin();
    IdentityValueArray::const_iterator end = values.end();
    std::ostringstream oss;

    while (beg != end)
    {
        oss << *beg;
        if (++beg != end)
            { oss << "\n"; }
    }
    return out << oss.str();
}

NAMESPACE_END

#endif  // CRYPTOPP_X509_CERTIFICATE_H
