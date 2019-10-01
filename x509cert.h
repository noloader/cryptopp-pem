// x509cert.h - X.509 certificate read and write routines.
//              Written and placed in the public domain by Jeffrey Walton and Geoff Beier

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

const ASNTag InvalidTag = static_cast<ASNTag>(0);

/// \brief X.500 Relative Distinguished Name value
struct RdnValue : public ASN1Object
{
    virtual ~RdnValue() {}
    RdnValue() : m_tag(InvalidTag) {}

    void BERDecode(BufferedTransformation &bt);
    void DEREncode(BufferedTransformation &bt) const;

    bool ValdateTag(byte tag) const;
    std::ostream& Print(std::ostream& out) const;

    std::string EncodeRdnValue() const;

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

    bool ValdateTag(byte tag) const;
    std::ostream& Print(std::ostream& out) const;

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

    bool ValdateTag(byte tag) const;
    std::ostream& Print(std::ostream& out) const;

    OID m_oid;
    SecByteBlock m_value;
    ASNTag m_tag;
    bool m_critical;
};

/// \brief Array of X.509 Extension values
typedef std::vector<ExtensionValue> ExtensionValueArray;

/// \brief Identity value
struct IdentityValue
{
    virtual ~IdentityValue() {}
    IdentityValue() : m_tag(InvalidTag) {}

    std::ostream& Print(std::ostream& out) const;

    OID m_oid;
    SecByteBlock m_value;
    ASNTag m_tag;
};

typedef std::vector<IdentityValue> IdentityValueArray;

/// \brief X.509 Certificate
/// \details X509Certificate is a partial implementation of X.509 certificate
///  parsing. The class loads a DER encoded certificate and presents many of
///  the more important attributes and values through accessor functions. The
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
    /// \param certificate SecByteBlock to receive the certificate
    const SecByteBlock& GetCertificate () const
	    { return m_origCertificate; }

    /// \brief Retrieve DER encoded ToBeSigned
    /// \param toBeSigned SecByteBlock to receive the toBeSigned
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
    const OID& GetCertificateSignatureAlgorithm() const
        { return m_certSignatureAlgortihm; }

    /// \brief Certificate signature
    /// \returns Certificate signature
    const SecByteBlock& GetCertificateSignature() const
        { return m_certSignature; }

    /// \brief Validity not before
    /// \returns Validity not before
    const DateValue& GetNotBefore() const
        { return m_notBefore; }

    /// \brief Validity not after
    /// \returns Validity not after
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

    /// \brief Certificate extensions
    /// \returns Certificate extensions array
	/// \details Certificate extensions are available with X.509 v3.
    const ExtensionValueArray& GetExtensions() const
        { return *m_extensions.get(); }

    /// \brief Subject public key
    /// \returns Subject public key
    const X509PublicKey& GetSubjectPublicKey() const
	    { return *m_subjectPublicKey.get(); }

	/// \brief Determine if optional attribute is present
	/// \returns true if an optional attribute is present, false otherwise
	bool HasOptionalAttribute(const BufferedTransformation &bt, byte tag) const;

	/// \brief Determine if Issuer UniqueId is present
	/// \returns true if if Issuer UniqueId is present, false otherwise
	/// \details Subject Issuer is available with X.509 v2.
	bool HasIssuerUniqueId() const
	    { return m_issuerUid.get() != NULLPTR; }

	/// \brief Determine if Subject UniqueId is present
	/// \returns true if if Subject UniqueId is present, false otherwise
	/// \details Subject UniqueId is available with X.509 v2.
	bool HasSubjectUniqueId() const
	    { return m_subjectUid.get() != NULLPTR; }

	/// \brief Determine if Extensions are present
	/// \returns true if if Extensions are present, false otherwise
	/// \details Extensions are available with X.509 v3.
	bool HasExtensions() const
	    { return m_extensions.get() != NULLPTR; }

    /// \brief Print a certificate
    /// \returns Print a certificate
	/// \details Print() displays some of the fields of a certificate for
	///  debug purposes. Users should modify the class to suit their taste
	///  or override this class in a derived class.
    virtual std::ostream& Print(std::ostream& out) const;

protected:
    // Crib away the original certificate
    void SaveCertificateBytes(BufferedTransformation &bt);

    void BERDecodeVersion(BufferedTransformation &bt, Version &version);
    void BERDecodeSignatureAlgorithm(BufferedTransformation &bt, OID &algorithm);
    void BERDecodeDistinguishedName(BufferedTransformation &bt, RdnValueArray &rdn);
    void BERDecodeValidity(BufferedTransformation &bt, DateValue &notBefore, DateValue &notAfter);
    void BERDecodeDate(BufferedTransformation &bt, DateValue &date);
    void BERDecodeSubjectPublicKeyInfo(BufferedTransformation &bt, member_ptr<X509PublicKey>& publicKey);

    // Optional parameters
    void BERDecodeIssuerUniqueId(BufferedTransformation &bt);
    void BERDecodeSubjectUniqueId(BufferedTransformation &bt);
    void BERDecodeExtensions(BufferedTransformation &bt);

	// BERDecodeSubjectPublicKeyInfo helper to get public key OIDs
	void GetSubjectPublicKeyInfoOids(BufferedTransformation &bt, OID& algorithm, OID& field) const;

private:
    Version m_version;
    Integer m_serialNumber;

	// certificate algorithm and signature
    OID m_certSignatureAlgortihm;
    SecByteBlock m_certSignature;

    RdnValueArray m_issuerName;
    RdnValueArray m_subjectName;

    DateValue m_notBefore, m_notAfter;

	// The one thing of value in this collection of bits
    member_ptr<X509PublicKey> m_subjectPublicKey;

    // Certificate v2, optional
    member_ptr<SecByteBlock> m_issuerUid;
    member_ptr<SecByteBlock> m_subjectUid;

    // Certificate v3, optional
    member_ptr<ExtensionValueArray> m_extensions;

    // Hack so we can examine the octets and verify the signature
    SecByteBlock m_origCertificate;
	mutable SecByteBlock m_toBeSigned;  // lazy
};

inline std::ostream& operator<<(std::ostream& out, const X509Certificate &cert)
    { return cert.Print(out); }
inline std::ostream& operator<<(std::ostream& out, const RdnValue &value)
    { return value.Print(out); }
inline std::ostream& operator<<(std::ostream& out, const DateValue &value)
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
		    { oss << ";"; }
    }
    return out << oss.str();
}

NAMESPACE_END

#endif  // CRYPTOPP_X509_CERTIFICATE_H
