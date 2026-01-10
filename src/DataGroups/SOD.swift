
import Foundation
import OpenSSL


@available(iOS 13, macOS 10.15, *)
class SOD : DataGroup {
    
    public private(set) var pkcs7CertificateData : [UInt8] = []
    private var asn1: ASN1Node!
    private var pubKey : OpaquePointer?

    override var datagroupType: DataGroupId { .SOD }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        self.pkcs7CertificateData = body
    }

    deinit {
        if ( pubKey != nil ) {
            EVP_PKEY_free(pubKey);
        }
    }

    override func parse(_ data: [UInt8]) throws {
        asn1 = try ASN1.parse(body)
    }
    
    /// Returns the public key from the embedded X509 certificate
    /// - Returns pointer to the public key
    func getPublicKey( ) throws -> OpaquePointer {
        
        if let key = pubKey {
            return key
        }
        
        let certs = try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der:Data(pkcs7CertificateData))
        if let key = X509_get_pubkey (certs[0].cert) {
            pubKey = key
            return key
        }
        
        throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Unable to get public key")
    }
    
    
    /// Extracts the encapsulated content section from a SignedData PKCS7 container (if present)
    /// - Returns: The encapsulated content from a PKCS7 container if we could read it
    /// - Throws: Error if we can't find or read the encapsulated content
    func getEncapsulatedContent() throws -> Data {
        guard let signedData = asn1[1]?[0],
              let encContent = signedData[2]?[1],
              let content = encContent[0] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        guard content.tag == .octetString else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned")
        }
        
        return content.dataValue
    }
    
    /// Gets the digest algorithm used to hash the encapsulated content in the signed data section (if present)
    /// - Returns: The digest algorithm used to hash the encapsulated content in the signed data section
    /// - Throws: Error if we can't find or read the digest algorithm
    func getEncapsulatedContentDigestAlgorithm() throws -> String {
        guard let signedData = asn1[1]?[0],
              let digestAlgo = signedData[1]?[0]?[0] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        guard let oid = digestAlgo.oidValue else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return ASN1.oidName(oid)
    }
    
    /// Gets the signed attributes section (if present)
    /// - Returns: the signed attributes section
    /// - Throws: Error if we can't find or read the signed attributes
    func getSignedAttributes( ) throws -> Data {
        
        // Get the SignedAttributes section.
        guard let signedData = asn1[1]?[0],
              let signerInfo = signedData[4],
              let signedAttrs = signerInfo[0]?[3] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        let start = signedAttrs.offset
        let totalLength = signedAttrs.headerLength + signedAttrs.contentLength
        var bytes = [UInt8](self.pkcs7CertificateData[start ..< start + totalLength])
        
        // The first byte will be 0xA0 -> as its a explicit tag for a contextual item which we need to convert
        // for the hash to calculate correctly
        // We know that the actual tag is a SET (0x31) - See section 5.4 of https://tools.ietf.org/html/rfc5652
        // So we need to change this from 0xA0 to 0x31
        if bytes[0] == 0xA0 {
            bytes[0] = 0x31
        }
        let signedAttribs = Data(bytes)
        
        return signedAttribs
    }
    
    /// Gets the message digest from the signed attributes section (if present)
    /// - Returns: the message digest
    /// - Throws: Error if we can't find or read the message digest
    func getMessageDigestFromSignedAttributes( ) throws -> Data {
        
        // For the SOD, the SignedAttributes consists of:
        // A Content type Object (which has the value of the attributes content type)
        // A messageDigest Object which has the message digest as it value
        // We want the messageDigest value
        
        guard let signedData = asn1[1]?[0],
              let signerInfo = signedData[4],
              let signedAttrs = signerInfo[0]?[3] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // Find the messageDigest in the signedAttributes section
        for i in 0..<signedAttrs.count {
            guard let attrObj = signedAttrs[i],
                  let attrType = attrObj[0],
                  attrType.oidValue == ASN1.OID.messageDigest else {
                continue
            }
            
            if let set = attrObj[1],
               let digestVal = set[0],
               digestVal.tag == .octetString {
                return digestVal.dataValue
            }
        }
        
        throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No messageDigest Returned")
    }
    
    /// Gets the signature data (if present)
    /// - Returns: the signature
    /// - Throws: Error if we can't find or read the signature
    func getSignature( ) throws -> Data {
        
        guard let signedData = asn1[1]?[0],
              let signerInfo = signedData[4],
              let signature = signerInfo[0]?[5] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        guard signature.tag == .octetString else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned")
        }
        
        return signature.dataValue
    }
    
    /// Gets the signature algorithm used (if present)
    /// - Returns: the signature algorithm used
    /// - Throws: Error if we can't find or read the signature algorithm
    func getSignatureAlgorithm( ) throws -> String {
        
        guard let signedData = asn1[1]?[0],
              let signerInfo = signedData[4],
              let signatureAlgo = signerInfo[0]?[4]?[0] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        guard let oid = signatureAlgo.oidValue else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // Vals I've seen are:
        // sha1WithRSAEncryption => default pkcs1
        // sha256WithRSAEncryption => default pkcs1
        // rsassaPss => pss        
        return ASN1.oidName(oid)
    }
}
