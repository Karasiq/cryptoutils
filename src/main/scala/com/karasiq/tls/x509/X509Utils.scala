package com.karasiq.tls.x509

import java.math.BigInteger
import java.security.PrivateKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions.{DigestAlgorithm, SignatureDigestAlgorithm}
import com.karasiq.tls.internal.TLSUtils
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.{X509CertificateHolder, X509ExtensionUtils}
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.operator.jcajce.{JcaContentSignerBuilder, JcaContentVerifierProviderBuilder, JcaDigestCalculatorProviderBuilder}
import org.bouncycastle.operator.{ContentSigner, ContentVerifierProvider}

object X509Utils {
  private val config = ConfigFactory.load().getConfig("karasiq.tls.x509-defaults")

  /**
   * Ensures that certificate usage as CA is allowed
   * @param certificate X509 certificate
   * @return Check result, or true if no extension present
   */
  def isCertificationAuthority(certificate: TLS.Certificate): Boolean = {
    val certHolder = new X509CertificateHolder(certificate)
    Option(BasicConstraints.fromExtensions(certHolder.getExtensions))
      .fold(true)(_.isCA)
  }

  /**
   * Returns chain path length constraint of CA certificate
   * @param certificate X509 certificate
   * @return Path length constraint, or None if no extension present
   */
  def getPathLengthConstraint(certificate: TLS.Certificate): Option[Int] = {
    val certHolder = new X509CertificateHolder(certificate)
    Option(BasicConstraints.fromExtensions(certHolder.getExtensions)).collect {
      case bc if bc.isCA && bc.getPathLenConstraint != null && bc.getPathLenConstraint.compareTo(BigInteger.ZERO) > 0 ⇒
        bc.getPathLenConstraint.intValue()
    }
  }

  /**
   * Ensures that specified key usages allowed
   * @param certificate X509 certificate
   * @param keyUsage Key usages
   * @return Check result, or true if no extension present
   */
  def isKeyUsageAllowed(certificate: TLS.Certificate, keyUsage: Int): Boolean = {
    Option(KeyUsage.fromExtensions(new X509CertificateHolder(certificate).getExtensions))
      .fold(true)(_.hasUsages(keyUsage))
  }

  /**
   * Reads subject alternative names (SANs) from certificate
   * @param certificate X509 certificate
   * @return Alternative names, or None if no extension present
   */
  def alternativeNamesOf(certificate: TLS.Certificate): Option[GeneralNames] = {
    val certHolder = new X509CertificateHolder(certificate)
    Option(GeneralNames.fromExtensions(certHolder.getExtensions, Extension.subjectAlternativeName))
  }

  /**
   * Reads specified subject alternative name (SAN) from certificate
   * @param certificate X509 certificate
   * @param nameId Alternative name ID
   * @return Alternative name, or None if no extension present
   */
  def alternativeNameOf(certificate: TLS.Certificate, nameId: Int): Option[ASN1Encodable] = {
    alternativeNamesOf(certificate).flatMap(_.getNames.find(_.getTagNo == nameId).map(_.getName))
  }

  private def verifyAlgorithms(): Seq[String] = {
    import scala.collection.JavaConversions._
    config.getStringList("key-id-verify-with")
  }

  /**
   * Compares issuer key identifier extension data with the actual issuer certificate
   * @param certificate Certificate
   * @param issuer Issuer certificate
   * @return Check result, or None if no extension present
   */
  def verifyAuthorityIdentifier(certificate: TLS.Certificate, issuer: TLS.Certificate): Option[Boolean] = {
    val certHolder = new X509CertificateHolder(certificate)
    Option(AuthorityKeyIdentifier.fromExtensions(certHolder.getExtensions)).map { keyId ⇒
      val utils = extensionUtils()
      val issuerId = utils.createAuthorityKeyIdentifier(new X509CertificateHolder(issuer))
      Option(keyId.getAuthorityCertIssuer).fold(true)(_ == issuerId.getAuthorityCertIssuer) &&
      Option(keyId.getAuthorityCertSerialNumber).fold(true)(_ == issuerId.getAuthorityCertSerialNumber) &&
        util.Arrays.equals(issuerId.getKeyIdentifier, keyId.getKeyIdentifier)
    }
  }

  /**
   * Compares subject public key identifier extension data with the actual public key
   * @param certificate Certificate
   * @param publicKey Public key info
   * @return Check result, or None if no extension present
   */
  def verifyPublicKeyIdentifier(certificate: TLS.Certificate, publicKey: SubjectPublicKeyInfo): Option[Boolean] = {
    val certHolder = new X509CertificateHolder(certificate)
    Option(SubjectKeyIdentifier.fromExtensions(certHolder.getExtensions)).map { keyId ⇒
      val utils = extensionUtils()
      val issuerId = utils.createSubjectKeyIdentifier(publicKey)
      util.Arrays.equals(issuerId.getKeyIdentifier, keyId.getKeyIdentifier)
    }
  }

  def getCrlDistributionUrls(certificate: TLS.Certificate): Seq[String] = {
    val urls = CertExtension.extensionsOf(certificate).collect {
      case CertExtension(Extension.cRLDistributionPoints, points, _) ⇒
        CRLDistPoint.getInstance(points).getDistributionPoints.flatMap {
          case point ⇒
            point.getCRLIssuer.getNames
              .filter(_.getTagNo == GeneralName.uniformResourceIdentifier)
              .map(_.getName.toString)
        }
    }
    urls.toSeq.flatten
  }

  def expireDays(days: Int): Instant = {
    Instant.now().plus(days, ChronoUnit.DAYS)
  }

  def defaultExpire(): Instant = {
    expireDays(config.getInt("expire-days"))
  }

  def defaultKeySize(algorithm: String = "RSA"): Int = {
    config.getInt(s"${algorithm.toLowerCase}-key-size")
  }

  def defaultSignatureHash(): String = {
    config.getString("sign-algorithm")
  }

  def defaultEllipticCurve(): ECParameterSpec = {
    TLSUtils.getEllipticCurve(config.getString("ecdsa-curve"))
  }

  def subject(commonName: String, country: String = null, state: String = null, locality: String = null, organization: String = null, organizationUnit: String = null, email: String = null): X500Name = {
    def checkLength(s: String, max: Int = 64, min: Int = 1): Unit = {
      assert(s.length >= min && s.length <= max, s"Invalid data length: $s")
    }

    val builder = new X500NameBuilder()
    assert(commonName ne null, "Common name required")
    checkLength(commonName)
    builder.addRDN(BCStyle.CN, commonName)

    if (country != null) {
      checkLength(country, 2, 2)
      builder.addRDN(BCStyle.C, country)
    }
    if (state != null) {
      checkLength(state)
      builder.addRDN(BCStyle.ST, state)
    }
    if (locality != null) {
      checkLength(locality)
      builder.addRDN(BCStyle.L, locality)
    }
    if (organization != null) {
      checkLength(organization)
      builder.addRDN(BCStyle.O, organization)
    }
    if (organizationUnit != null) {
      checkLength(organizationUnit)
      builder.addRDN(BCStyle.OU, organizationUnit)
    }
    if (email != null) {
      builder.addRDN(BCStyle.E, email)
    }

    builder.build()
  }

  private[tls] def contentVerifierProvider(certificate: TLS.Certificate): ContentVerifierProvider = {
    new JcaContentVerifierProviderBuilder()
      .setProvider(TLSUtils.provider)
      .build(new X509CertificateHolder(certificate))
  }
  
  private[tls] def contentSigner(key: PrivateKey, hashAlg: String = defaultSignatureHash()): ContentSigner = {
    new JcaContentSignerBuilder(SignatureDigestAlgorithm(key.getAlgorithm, hashAlg))
      .setProvider(TLSUtils.provider)
      .build(key)
  }

  private[tls] def extensionUtils(digest: String = config.getString("key-id-algorithm")): X509ExtensionUtils = {
    val calculator = new JcaDigestCalculatorProviderBuilder()
      .setProvider(TLSUtils.provider)
      .build()
      .get(DigestAlgorithm(digest))

    new X509ExtensionUtils(calculator)
  }
}
