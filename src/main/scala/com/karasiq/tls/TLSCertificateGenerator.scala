package com.karasiq.tls

import java.security._
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date

import com.karasiq.tls.TLSCertificateGenerator.CertExtension
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.TLSUtils
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.bouncycastle.asn1.x509._
import org.bouncycastle.asn1.{ASN1Encodable, ASN1ObjectIdentifier}
import org.bouncycastle.cert.{X509CertificateHolder, X509ExtensionUtils, X509v3CertificateBuilder}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.operator.jcajce.{JcaContentSignerBuilder, JcaDigestCalculatorProviderBuilder}
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder

import scala.util.Try

object TLSCertificateGenerator {
  private val config = ConfigFactory.load().getConfig("karasiq.tls.x509-defaults")

  private val provider = new BouncyCastleProvider

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

  def signatureAlgorithmFor(keyAlg: String, hashAlg: String = defaultSignatureHash()): String = {
    s"${hashAlg.replace("-", "").toUpperCase}with${keyAlg.toUpperCase}"
  }

  def ellipticCurve(name: String): ECParameterSpec = {
    Option(ECNamedCurveTable.getParameterSpec(name))
      .getOrElse(throw new IllegalArgumentException("Elliptic curve not defined: " + name))
  }

  def defaultEllipticCurve(): ECParameterSpec = {
    ellipticCurve(config.getString("ecdsa-curve"))
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

  def apply(): TLSCertificateGenerator = new TLSCertificateGenerator

  case class CertExtension(id: ASN1ObjectIdentifier, value: ASN1Encodable, critical: Boolean = false) {
    require(id ne null)

    override def equals(obj: scala.Any): Boolean = obj match {
      case CertExtension(oid, _, _) ⇒
        this.id == oid

      case _ ⇒
        false
    }

    override def hashCode(): Int = id.hashCode()
  }

  object CertExtension {
    private def digestId(): AlgorithmIdentifier = {
      val name = config.getString("sign-algorithm")
      Try(AlgorithmIdentifier.getInstance(classOf[NISTObjectIdentifiers].getField("id_" + name.replace("-", "").toLowerCase).get(null).asInstanceOf[ASN1ObjectIdentifier]))
        .getOrElse(throw new IllegalArgumentException("Invalid digest identifier: " + name))
    }

    private def extensionUtils(): X509ExtensionUtils = {
      val calculator = new JcaDigestCalculatorProviderBuilder()
        .setProvider(provider)
        .build()
        .get(digestId())

      new X509ExtensionUtils(calculator)
    }

    def load(extensionsHolder: Extensions): Set[CertExtension] = {
      val critical = extensionsHolder.getCriticalExtensionOIDs.map { oid ⇒
        CertExtension(oid, extensionsHolder.getExtension(oid).getParsedValue, critical = true)
      }

      val extensions = extensionsHolder.getExtensionOIDs.map { oid ⇒
        CertExtension(oid, extensionsHolder.getExtension(oid).getParsedValue, critical = false)
      }
      critical.toSet ++ extensions.toSet
    }

    def load(cert: TLS.Certificate): Set[CertExtension] = {
      load(new X509CertificateHolder(cert).getExtensions)
    }
    
    def basicConstraints(ca: Boolean = false): CertExtension = {
      CertExtension(Extension.basicConstraints, new BasicConstraints(ca))
    }

    def keyUsage(usage: Int = KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.nonRepudiation): CertExtension = {
      CertExtension(Extension.keyUsage, new KeyUsage(usage))
    }

    def identifiers(key: PublicKey, issuer: Option[TLS.CertificateKey] = None): Set[CertExtension] = {
      val utils = extensionUtils()
      Set(CertExtension(Extension.subjectKeyIdentifier, utils.createSubjectKeyIdentifier(key.toSubjectPublicKeyInfo))) ++ issuer.map { cert ⇒
        CertExtension(Extension.authorityKeyIdentifier, utils.createAuthorityKeyIdentifier(new X509CertificateHolder(cert.certificate)))
      }
    }

    def alternativeName(otherName: String = null, rfc822Name: String = null, dNSName: String = null, x400Address: String = null, directoryName: String = null, ediPartyName: String = null, uniformResourceIdentifier: String = null, iPAddress: String = null, registeredID: String = null, extensionId: ASN1ObjectIdentifier = Extension.subjectAlternativeName): CertExtension = {
      val names = Seq(
        Option(otherName).map(new GeneralName(GeneralName.otherName, _)),
        Option(rfc822Name).map(new GeneralName(GeneralName.rfc822Name, _)),
        Option(dNSName).map(new GeneralName(GeneralName.dNSName, _)),
        Option(x400Address).map(new GeneralName(GeneralName.x400Address, _)),
        Option(directoryName).map(new GeneralName(GeneralName.directoryName, _)),
        Option(ediPartyName).map(new GeneralName(GeneralName.ediPartyName, _)),
        Option(uniformResourceIdentifier).map(new GeneralName(GeneralName.uniformResourceIdentifier, _)),
        Option(iPAddress).map(new GeneralName(GeneralName.iPAddress, _)),
        Option(registeredID).map(new GeneralName(GeneralName.registeredID, _))
      )
      CertExtension(extensionId, new GeneralNames(names.flatten.toArray))
    }
  }

  def defaultExtensions(): Set[CertExtension] = {
    Set(CertExtension.basicConstraints(false), CertExtension.keyUsage())
  }
}

class TLSCertificateGenerator {
  protected val provider: java.security.Provider = new BouncyCastleProvider
  protected val secureRandom: SecureRandom = new SecureRandom()

  private def makeChain(issuer: TLS.CertificateChain, certificate: TLS.Certificate): TLS.CertificateChain = {
    new TLS.CertificateChain(Array(certificate) ++ issuer.getCertificateList)
  }

  /**
   * Creates PKCS10 certification request
   * @param keyPair Key pair
   * @param subject Certificate subject
   * @param extensions X509 extensions
   * @return Certification request
   */
  def createRequest(keyPair: KeyPair, subject: X500Name, extensions: Set[CertExtension] = TLSCertificateGenerator.defaultExtensions()): PKCS10CertificationRequest = {
    val contentSigner = new JcaContentSignerBuilder(TLSCertificateGenerator.signatureAlgorithmFor(keyPair.getPrivate.getAlgorithm))
      .setProvider(provider)
      .build(keyPair.getPrivate)

    val builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic)
    val extGen = new ExtensionsGenerator()
    extensions.foreach { e ⇒
      extGen.addExtension(e.id, e.critical, e.value)
    }
    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
    builder.build(contentSigner)
  }

  /**
   * Signs certification request and creates X509 certificate
   * @param request Certification request
   * @param issuer Certificate issuer
   * @param serial Certificate serial number
   * @param notAfter Certificate expiration date
   * @param extensions X509 extensions
   * @return X509 certificate
   */
  def signRequest(request: PKCS10CertificationRequest, issuer: TLS.CertificateKey, serial: BigInt = BigInt(1), notAfter: Instant = TLSCertificateGenerator.defaultExpire(), extensions: Set[CertExtension] = Set.empty): TLS.CertificateChain = {
    val signKey = issuer.key.getPrivate.toPrivateKey
    val contentSigner = new JcaContentSignerBuilder(TLSCertificateGenerator.signatureAlgorithmFor(signKey.getAlgorithm))
      .setProvider(provider)
      .build(signKey)

    val certificateBuilder = new X509v3CertificateBuilder(issuer.certificate.getSubject, serial.underlying(), new Date(), Date.from(notAfter),
      request.getSubject, request.getSubjectPublicKeyInfo)

    val csrExtensions: Set[CertExtension] = Try(CertExtension.load(Extensions.getInstance(request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest).head.getAttrValues.getObjectAt(0)))).getOrElse(Set())

    (extensions ++ CertExtension.identifiers(request.getSubjectPublicKeyInfo.toPublicKey, Some(issuer)) ++ csrExtensions).foreach { ext ⇒
      certificateBuilder.addExtension(ext.id, ext.critical, ext.value)
    }

    makeChain(issuer.certificateChain, certificateBuilder.build(contentSigner).toASN1Structure)
  }

  /**
   * Creates X509 certificate from provided key pair
   * @param keyPair Asymmetric cipher key pair
   * @param subject Certificate subject
   * @param issuer Certificate issuer (None = self-signed)
   * @param serial Certificate serial number
   * @param notAfter Certificate expiration date
   * @param extensions X509 extensions
   * @return Created certificate
   */
  def create(keyPair: KeyPair, subject: X500Name, issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = TLSCertificateGenerator.defaultExpire(), extensions: Set[CertExtension] = TLSCertificateGenerator.defaultExtensions()): TLS.CertificateKey = {
    val signKey = issuer.fold(keyPair.getPrivate)(_.key.getPrivate.toPrivateKey)

    val contentSigner = new JcaContentSignerBuilder(TLSCertificateGenerator.signatureAlgorithmFor(signKey.getAlgorithm))
      .setProvider(provider)
      .build(signKey)

    val certificateBuilder = new X509v3CertificateBuilder(issuer.fold(subject)(_.certificate.getSubject), serial.underlying(), new Date(), Date.from(notAfter),
      subject, keyPair.getPublic.toSubjectPublicKeyInfo)

    (extensions ++ CertExtension.identifiers(keyPair.getPublic, issuer)).foreach {
      case CertExtension(id, value, critical) ⇒
        certificateBuilder.addExtension(id, critical, value)
    }

    val certificate = certificateBuilder.build(contentSigner).toASN1Structure
    TLS.CertificateKey(issuer.fold(certificate.toTlsCertificateChain)(is ⇒ makeChain(is.certificateChain, certificate)), keyPair.toAsymmetricCipherKeyPair)
  }

  /**
   * Generates new key pair with specified algorithm and creates X509 certificate for it
   * @param subject Certificate subject
   * @param algorithm Key pair generation algorithm
   * @param size Key size in bits
   * @param issuer Certificate issuer (None = self-signed)
   * @param serial Certificate serial number
   * @param notAfter Certificate expiration date
   * @param extensions X509 extensions
   * @return Created certificate and key pair
   */
  def generate(subject: X500Name, algorithm: String = "RSA", size: Int = 0, issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = TLSCertificateGenerator.defaultExpire(), extensions: Set[CertExtension] = TLSCertificateGenerator.defaultExtensions()): TLS.CertificateKey = {
    issuer.foreach { ca ⇒
      assert(TLSUtils.isCertificateAuthority(ca.certificate) && TLSUtils.isKeyUsageAllowed(ca.certificate, KeyUsage.keyCertSign),
        s"Certificate signing disallowed by extensions: ${ca.certificate.getSubject}")
    }

    val generator = KeyPairGenerator.getInstance(algorithm, provider)
    generator.initialize(if (size == 0) TLSCertificateGenerator.defaultKeySize(algorithm) else size, secureRandom)
    val keyPair = generator.generateKeyPair()
    create(keyPair, subject, issuer, serial, notAfter, extensions)
  }

  /**
   * Generates new ECDSA key pair and creates X509 certificate for it
   * @param subject Certificate subject
   * @param curve Elliptic curve for key generation
   * @param issuer Certificate issuer (None = self-signed)
   * @param serial Certificate serial number
   * @param notAfter Certificate expiration date
   * @param extensions X509 extensions
   * @return Created certificate and key pair
   */
  def generateEcdsa(subject: X500Name, curve: ECParameterSpec = TLSCertificateGenerator.defaultEllipticCurve(), issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = TLSCertificateGenerator.defaultExpire(), extensions: Set[CertExtension] = TLSCertificateGenerator.defaultExtensions()): TLS.CertificateKey = {
    val keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", provider)
    keyPairGenerator.initialize(curve, secureRandom)
    val keyPair = keyPairGenerator.generateKeyPair()
    create(keyPair, subject, issuer, serial, notAfter, extensions)
  }

  /**
   * Generates key/certificate set for all algorithms
   * @param subject Certificate subject
   * @param rsaSize RSA key size in bits
   * @param dsaSize DSA key size in bits
   * @param curve Elliptic curve for key generation
   * @param issuer Certificate issuer (None = self-signed)
   * @param serial Certificate serial number
   * @param notAfter Certificate expiration date
   * @param extensions X509 extensions
   * @return Created certificate and key pair
   */
  def generateKeySet(subject: X500Name, rsaSize: Int = TLSCertificateGenerator.defaultKeySize("RSA"), dsaSize: Int = TLSCertificateGenerator.defaultKeySize("DSA"), curve: ECParameterSpec = TLSCertificateGenerator.defaultEllipticCurve(), issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = TLSCertificateGenerator.defaultExpire(), extensions: Set[CertExtension] = TLSCertificateGenerator.defaultExtensions()): TLS.KeySet = {
    val rsa = generate(subject, "RSA", rsaSize, issuer, serial, notAfter, extensions)
    val dsa = generate(subject, "DSA", dsaSize, issuer, serial, notAfter, extensions)
    val ecdsa = generateEcdsa(subject, curve, issuer, serial, notAfter, extensions)
    TLS.KeySet(Some(rsa), Some(dsa), Some(ecdsa))
  }
}
