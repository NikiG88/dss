/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.model.x509;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureValidity;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.identifier.CertificateTokenIdentifier;
import eu.europa.esig.dss.model.identifier.EntityIdentifier;
import eu.europa.esig.dss.model.identifier.EntityIdentifierBuilder;
import eu.europa.esig.dss.model.identifier.TokenIdentifier;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Whenever the signature validation process encounters an {@link java.security.cert.X509Certificate} a certificateToken
 * is created.<br>
 * This class encapsulates some frequently used information: a certificate comes from a certain context (Trusted List,
 * CertStore, Signature), has revocation data... To expedite the processing of such information, they are kept in cache.
 */
@SuppressWarnings("serial")
public class CertificateToken extends Token {

    /**
     * Encapsulated X509 certificate.
     */
    private final X509Certificate x509Certificate;

    /**
     * Digest of the public key (cross certificates have same public key)
     */
    private final EntityIdentifier entityKey;

    /**
     * Indicates if the certificate is self-signed. This attribute stays null till the first call to
     * {@link #isSelfSigned()} function.
     */
    private Boolean selfSigned;

    /**
     * Cached list of KeyUsageBit
     */
    private List<KeyUsageBit> keyUsageBits;

    /**
     * URL used to download a certificate from (used in aia.caIssuers download operation)
     */
    private String sourceURL;

    /**
     * Cached SHA-1 of the subjectPublicKey BIT STRING (RFC 5280, 4.2.1.2 method 1). This attribute stays null till
     * the first call to {@link #getPublicKeySki()} function.
     */
    private transient volatile byte[] publicKeySki;

    /**
     * Creates a CertificateToken wrapping the provided X509Certificate.
     *
     * @param x509Certificate the X509Certificate object
     */
    public CertificateToken(X509Certificate x509Certificate) {
        Objects.requireNonNull(x509Certificate, "X509 certificate is missing");

        this.x509Certificate = x509Certificate;
        this.entityKey = new EntityIdentifierBuilder(x509Certificate.getPublicKey(), x509Certificate.getSubjectX500Principal()).build();

        // The Algorithm OID is used and not the name {@code x509Certificate.getSigAlgName()}
        this.signatureAlgorithm = SignatureAlgorithm.forOidAndParams(x509Certificate.getSigAlgOID(), x509Certificate.getSigAlgParams());
    }

    @Override
    public String getAbbreviation() {
        return getDSSIdAsString();
    }

    /**
     * Returns the identifier of the current entity key (public key + subject name).
     * Several certificate can have the same entity key (cross-certificates)
     *
     * @return {@link EntityIdentifier}
     */
    public EntityIdentifier getEntityKey() {
        return entityKey;
    }

    @Override
    public EntityIdentifier getIssuerEntityKey() {
        if (isSelfSigned()) {
            return new EntityIdentifierBuilder(getPublicKey(), getSubject().getPrincipal()).build();
        } else {
            return super.getIssuerEntityKey();
        }
    }

    /**
     * Returns the public key associated with the certificate.<br>
     * To get the encryption algorithm used with this public key call getAlgorithm() method.<br>
     * RFC 2459:<br>
     * 4.1.2.7 Subject Public Key Info
     * This field is used to carry the public key and identify the algorithm with which the key is used. The algorithm
     * is
     * identified using the AlgorithmIdentifier structure specified in section 4.1.1.2. The object identifiers for the
     * supported algorithms and the methods for encoding the public key materials (public key and parameters) are
     * specified in section 7.3.
     *
     * @return the public key of the certificate
     */
    public PublicKey getPublicKey() {
        return x509Certificate.getPublicKey();
    }

    /**
     * Returns the SHA-1 digest of the certificate's subjectPublicKey BIT STRING value (excluding the tag, the length
     * and the number of unused bits), as defined in RFC 5280, section 4.2.1.2, method (1).
     * The value is computed once per token and is used to match a key-based identifier (e.g. OCSP ResponderID byKey).
     *
     * @return a copy of the SHA-1 digest of the subjectPublicKey
     */
    public byte[] getPublicKeySki() {
        byte[] ski = publicKeySki;
        if (ski == null) {
            ski = computePublicKeySki(getPublicKey());
            publicKeySki = ski;
        }
        return ski.clone();
    }

    private static byte[] computePublicKeySki(PublicKey publicKey) {
        try {
            return DigestAlgorithm.SHA1.getMessageDigest().digest(getSubjectPublicKeyBits(publicKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new DSSException(String.format("Unable to compute ski from public key : %s", e.getMessage()), e);
        }
    }

    /**
     * Extracts the subjectPublicKey bits from a DER-encoded SubjectPublicKeyInfo:
     * SEQUENCE { algorithm AlgorithmIdentifier (SEQUENCE), subjectPublicKey BIT STRING }
     */
    private static byte[] getSubjectPublicKeyBits(byte[] encoded) {
        if (encoded == null) {
            throw new DSSException("Unable to compute ski from public key : no encoded form");
        }
        int[] spki = readDerHeader(encoded, 0, 0x30);
        if (spki[0] + spki[1] != encoded.length) {
            throw new DSSException("Unable to compute ski from public key : unexpected SubjectPublicKeyInfo length");
        }
        int[] algorithm = readDerHeader(encoded, spki[0], 0x30);
        int[] bitString = readDerHeader(encoded, algorithm[0] + algorithm[1], 0x03);
        if (bitString[1] < 1 || encoded[bitString[0]] != 0) {
            throw new DSSException("Unable to compute ski from public key : subjectPublicKey is not octet aligned");
        }
        return Arrays.copyOfRange(encoded, bitString[0] + 1, bitString[0] + bitString[1]);
    }

    /**
     * Reads a DER tag and definite length at {@code offset}.
     *
     * @return {contentOffset, contentLength}
     */
    private static int[] readDerHeader(byte[] der, int offset, int expectedTag) {
        if (offset + 2 > der.length || (der[offset] & 0xFF) != expectedTag) {
            throw new DSSException(String.format("Unable to compute ski from public key : expected DER tag 0x%02X", expectedTag));
        }
        int first = der[offset + 1] & 0xFF;
        int position = offset + 2;
        int length;
        if (first < 0x80) {
            length = first;
        } else {
            int lengthBytes = first & 0x7F;
            if (lengthBytes == 0 || lengthBytes > 4 || position + lengthBytes > der.length) {
                throw new DSSException("Unable to compute ski from public key : unsupported DER length");
            }
            length = 0;
            for (int i = 0; i < lengthBytes; i++) {
                length = (length << 8) | (der[position++] & 0xFF);
            }
        }
        if (length < 0 || length > der.length - position) {
            throw new DSSException("Unable to compute ski from public key : truncated DER content");
        }
        return new int[] { position, length };
    }

    /**
     * Returns the expiration date of the certificate.
     *
     * @return the expiration date (notAfter)
     */
    public Date getNotAfter() {
        return x509Certificate.getNotAfter();
    }

    /**
     * Returns the issuance date of the certificate.
     *
     * @return the issuance date (notBefore)
     */
    public Date getNotBefore() {
        return x509Certificate.getNotBefore();
    }

    @Override
    public Date getCreationDate() {
        return getNotBefore();
    }

    /**
     * Gets certificate's source URL
     *
     * @return {@link String}
     */
    public String getSourceURL() {
        return sourceURL;
    }

    /**
     * Sets certificate's source URL
     *
     * @param sourceURL {@link String}
     */
    public void setSourceURL(String sourceURL) {
        this.sourceURL = sourceURL;
    }

    /**
     * Checks if the given date is in the validity period of the certificate.
     *
     * @param date the date to be tested
     * @return true if the given date is in the certificate period validity
     */
    public boolean isValidOn(final Date date) {
        if ((x509Certificate == null) || (date == null)) {
            return false;
        }
        try {
            x509Certificate.checkValidity(date);
            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            return false;
        }
    }

    /**
     * Checks if the certificate is self-signed.
     * <p>
     * "Self-signed certificates are self-issued certificates where the digital signature may be verified by the public
     * key bound into the certificate. Self-signed certificates are used to convey a public key for use to begin
     * certification paths." [RFC5280]
     *
     * @return true if the certificate is a self-sign
     */
    @Override
    public boolean isSelfSigned() {
        if (selfSigned == null) {
            selfSigned = isSelfIssued();
            if (selfSigned) {
                try {
                    x509Certificate.verify(x509Certificate.getPublicKey());
                    selfSigned = true;
                    signatureValidity = SignatureValidity.VALID;
                } catch (Exception e) {
                    selfSigned = false;
                }
            }
        } else if (selfSigned) {
            signatureValidity = SignatureValidity.VALID;
        }
        return selfSigned;
    }

    /**
     * This method returns true if the certificate is self-issued.
     * <p>
     * "Self-issued certificates are CA certificates in which the issuer and subject are the same entity.
     * Self-issued certificates are generated to support changes in policy or operations." [RFC5280]
     *
     * @return true if the certificate is self-issued
     */
    public boolean isSelfIssued() {
        return Arrays.equals(x509Certificate.getSubjectX500Principal().getEncoded(), x509Certificate.getIssuerX500Principal().getEncoded());
    }

    /**
     * This method returns true if the given token is equivalent.
     *
     * @param token the token to be compared
     * @return true if the given certificate has the same public key
     */
    public boolean isEquivalent(CertificateToken token) {
        PublicKey currentPublicKey = getPublicKey();
        PublicKey tokenPublicKey = token.getPublicKey();
        return Arrays.equals(currentPublicKey.getEncoded(), tokenPublicKey.getEncoded());
    }

    /**
     * Gets the enclosed X509 Certificate.
     *
     * @return the X509Certificate object
     */
    public X509Certificate getCertificate() {
        return x509Certificate;
    }

    /**
     * Returns the encoded form of this certificate. X.509 certificates would be encoded as ASN.1 DER.
     *
     * @return the encoded form of this certificate
     */
    @Override
    public byte[] getEncoded() {
        try {
            return x509Certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new DSSException("Unable to encode the certificate", e);
        }
    }

    /**
     * Gets the serialNumber value from the encapsulated certificate. The serial number is an integer assigned by the
     * certification authority to each certificate. It must be unique for each certificate issued by a given CA.
     *
     * @return the certificate serial number
     */
    public BigInteger getSerialNumber() {
        return x509Certificate.getSerialNumber();
    }

    /**
     * Returns the subject as wrapped X500Principal with helpful methods
     *
     * @return an instance of X500PrincipalHelper with the SubjectX500Principal
     */
    public X500PrincipalHelper getSubject() {
        return new X500PrincipalHelper(x509Certificate.getSubjectX500Principal());
    }

    /**
     * Returns the issuer as wrapped X500Principal with helpful methods
     *
     * @return an instance of X500PrincipalHelper with the IssuerX500Principal
     */
    public X500PrincipalHelper getIssuer() {
        return new X500PrincipalHelper(x509Certificate.getIssuerX500Principal());
    }

    /**
     * Returns the {@code X500Principal} of the certificate which was used to sign
     * this token.
     *
     * @return the issuer's {@code X500Principal}
     */
    @Override
    public X500Principal getIssuerX500Principal() {
        return x509Certificate.getIssuerX500Principal();
    }

    @Override
    protected SignatureValidity checkIsSignedBy(final PublicKey publicKey) {
        SignatureValidity result = SignatureValidity.INVALID;
        signatureInvalidityReason = "";
        try {
            x509Certificate.verify(publicKey);
            result = SignatureValidity.VALID;
        } catch (NoSuchProviderException e) { // if there's no default provider.
            throw new DSSException(String.format("No provider has been found for signature validation : %s", e.getMessage()), e);
        } catch (Exception e) {
            signatureInvalidityReason = e.getClass().getSimpleName() + " : " + e.getMessage();
        }
        signatureValidity = result;
        return result;
    }

    /**
     * This method checks if the certificate contains the given key usage bit.
     *
     * @param keyUsageBit the keyUsageBit to be checked.
     * @return true if contains
     */
    public boolean checkKeyUsage(final KeyUsageBit keyUsageBit) {
        return getKeyUsageBits().contains(keyUsageBit);
    }

    /**
     * This method returns a list {@code KeyUsageBit} representing the key usages of the certificate.
     *
     * @return {@code List} of {@code KeyUsageBit}s of different certificate's key usages
     */
    public List<KeyUsageBit> getKeyUsageBits() {
        if (keyUsageBits == null) {
            keyUsageBits = new ArrayList<>();
            final boolean[] keyUsageArray = x509Certificate.getKeyUsage();
            if (keyUsageArray != null && keyUsageArray.length > 0) {
                for (KeyUsageBit keyUsageBit : KeyUsageBit.values()) {
                    int index = keyUsageBit.getIndex();
                    if (keyUsageArray.length > index && keyUsageArray[index]) {
                        keyUsageBits.add(keyUsageBit);
                    }
                }
            }
        }
        return keyUsageBits;
    }

    /**
     * This method checks if the BasicConstraint is present
     *
     * @return true if the certificate is defined as a CA
     */
    public boolean isCA() {
        return x509Certificate.getBasicConstraints() != -1;
    }

    /**
     * This method returns a PathLenConstraint value when BasicConstraint and the attribute itself are present,
     * and cA parameters is set to true.
     *
     * @return PathLenConstraint integer value, when present. -1 otherwise
     */
    public int getPathLenConstraint() {
        return x509Certificate.getBasicConstraints();
    }

    /**
     * The signature value of the certificate
     *
     * @return the signature value
     */
    public byte[] getSignature() {
        return x509Certificate.getSignature();
    }

    @Override
    protected TokenIdentifier buildTokenIdentifier() {
        return new CertificateTokenIdentifier(this);
    }

    @Override
    public String toString(String indentStr) {
        final StringBuilder out = new StringBuilder();
        out.append(indentStr).append("CertificateToken[\n");
        indentStr += "\t";

        out.append(indentStr).append("DSS Id              : ").append(getDSSIdAsString()).append('\n');
        out.append(indentStr).append("Identity Id         : ").append(getEntityKey()).append('\n');
        out.append(indentStr).append("Validity period     : ").append(x509Certificate.getNotBefore()).append(" - ").append(x509Certificate.getNotAfter()).append('\n');
        out.append(indentStr).append("Subject name        : ").append(getSubject().getCanonical()).append('\n');
        out.append(indentStr).append("Issuer subject name : ").append(getIssuer().getCanonical()).append('\n');
        out.append(indentStr).append("Serial Number       : ").append(getSerialNumber()).append('\n');
        out.append(indentStr).append("Signature algorithm : ").append(signatureAlgorithm == null ? "?" : signatureAlgorithm).append('\n');

        if (isSelfSigned()) {
            out.append(indentStr).append("[SELF-SIGNED]").append('\n');
        }

        indentStr = indentStr.substring(1);
        out.append(indentStr).append(']');
        return out.toString();
    }

}
