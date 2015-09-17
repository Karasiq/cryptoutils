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
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.bouncycastle.asn1.x509._
import org.bouncycastle.asn1.{ASN1Encodable, ASN1ObjectIdentifier}
import org.bouncycastle.cert.{X509CertificateHolder, X509ExtensionUtils, X509v3CertificateBuilder}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.operator.jcajce.{JcaContentSignerBuilder, JcaDigestCalculatorProviderBuilder}

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

  def subject(commonName: String, country: String = "AU", state: String = "Unknown", locality: String = "Unknown", organization: String = "Unknown", organizationUnit: String = "Unknown", email: String = "Unknown"): X500Name = {
    def checkLength(s: String, max: Int = 64, min: Int = 1) = {
      assert(s.length >= min && s.length <= max, s"Invalid data length: $s")
    }

    checkLength(country, 2, 2)
    checkLength(commonName)
    checkLength(state)
    checkLength(locality)
    checkLength(organization)
    checkLength(organizationUnit)

    new X500NameBuilder()
      .addRDN(BCStyle.CN, commonName)
      .addRDN(BCStyle.C, country)
      .addRDN(BCStyle.ST, state)
      .addRDN(BCStyle.L, locality)
      .addRDN(BCStyle.O, organization)
      .addRDN(BCStyle.OU, organizationUnit)
      .addRDN(BCStyle.E, email)
      .build()
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

    def load(cert: TLS.Certificate): Set[CertExtension] = {
      val extensionsHolder = new X509CertificateHolder(cert).getExtensions
      val critical = extensionsHolder.getCriticalExtensionOIDs.map { oid ⇒
        CertExtension(oid, extensionsHolder.getExtension(oid), critical = true)
      }

      val extensions = extensionsHolder.getExtensionOIDs.map { oid ⇒
        CertExtension(oid, extensionsHolder.getExtension(oid), critical = false)
      }
      critical.toSet ++ extensions.toSet
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
   * Creates X509 certificate from provided key pair
   * @param keyPair Asymmetric cipher key pair
   * @param subject Certificate subject
   * @param issuer Certificate issuer (None = self-signed)
   * @param serial Certificate serial number
   * @param notAfter Certificate expiration date
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
   * @return Created certificate and key pair
   */
  def generateKeySet(subject: X500Name, rsaSize: Int = TLSCertificateGenerator.defaultKeySize("RSA"), dsaSize: Int = TLSCertificateGenerator.defaultKeySize("DSA"), curve: ECParameterSpec = TLSCertificateGenerator.defaultEllipticCurve(), issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = TLSCertificateGenerator.defaultExpire(), extensions: Set[CertExtension] = TLSCertificateGenerator.defaultExtensions()): TLS.KeySet = {
    val rsa = generate(subject, "RSA", rsaSize, issuer, serial, notAfter, extensions)
    val dsa = generate(subject, "DSA", dsaSize, issuer, serial, notAfter, extensions)
    val ecdsa = generateEcdsa(subject, curve, issuer, serial, notAfter, extensions)
    TLS.KeySet(Some(rsa), Some(dsa), Some(ecdsa))
  }
}
