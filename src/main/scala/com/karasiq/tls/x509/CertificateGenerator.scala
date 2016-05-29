package com.karasiq.tls.x509

import java.security._
import java.time.Instant
import java.util.Date

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.TLSUtils
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder

object CertificateGenerator {
  def apply(): CertificateGenerator = new CertificateGenerator
}

class CertificateGenerator {
  protected val secureRandom: SecureRandom = SecureRandom.getInstanceStrong

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
  def createRequest(keyPair: KeyPair, subject: X500Name, extensions: Set[CertExtension] = CertExtension.defaultExtensions()): PKCS10CertificationRequest = {
    val contentSigner = X509Utils.contentSigner(keyPair.getPrivate)
    val builder = new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic)
    builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, CSRUtils.encodeExtensions(extensions))
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
  def signRequest(request: PKCS10CertificationRequest, issuer: TLS.CertificateKey, serial: BigInt = BigInt(1), notAfter: Instant = X509Utils.defaultExpire(), extensions: Set[CertExtension] = Set.empty): TLS.CertificateChain = {
    val signKey = issuer.key.getPrivate.toPrivateKey
    val contentSigner = X509Utils.contentSigner(signKey)

    val certificateBuilder = new X509v3CertificateBuilder(issuer.certificate.getSubject, serial.underlying(), new Date(), Date.from(notAfter),
      request.getSubject, request.getSubjectPublicKeyInfo)
    
    (extensions ++ CertExtension.identifiers(request.getSubjectPublicKeyInfo, Some(issuer.certificate)) ++ CSRUtils.extensionsOf(request)).foreach { ext ⇒
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
  def create(keyPair: KeyPair, subject: X500Name, issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = X509Utils.defaultExpire(), extensions: Set[CertExtension] = CertExtension.defaultExtensions()): TLS.CertificateKey = {
    val signKey = issuer.fold(keyPair.getPrivate)(_.key.getPrivate.toPrivateKey)
    val contentSigner = X509Utils.contentSigner(signKey)
    val certificateBuilder = new X509v3CertificateBuilder(issuer.fold(subject)(_.certificate.getSubject), serial.underlying(), new Date(), Date.from(notAfter),
      subject, keyPair.getPublic.toSubjectPublicKeyInfo)

    (extensions ++ CertExtension.identifiers(keyPair.getPublic.toSubjectPublicKeyInfo, issuer.map(_.certificate))).foreach {
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
  def generate(subject: X500Name, algorithm: String = "RSA", size: Int = 0, issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = X509Utils.defaultExpire(), extensions: Set[CertExtension] = CertExtension.defaultExtensions()): TLS.CertificateKey = {
    issuer.foreach { ca ⇒
      assert(X509Utils.isCertificationAuthority(ca.certificate) && X509Utils.isKeyUsageAllowed(ca.certificate, KeyUsage.keyCertSign),
        s"Certificate signing disallowed by extensions: ${ca.certificate.getSubject}")
    }

    val generator = KeyPairGenerator.getInstance(algorithm, TLSUtils.provider)
    generator.initialize(if (size == 0) X509Utils.defaultKeySize(algorithm) else size, secureRandom)
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
  def generateEcdsa(subject: X500Name, curve: ECParameterSpec = X509Utils.defaultEllipticCurve(), issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = X509Utils.defaultExpire(), extensions: Set[CertExtension] = CertExtension.defaultExtensions()): TLS.CertificateKey = {
    val keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", TLSUtils.provider)
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
  def generateKeySet(subject: X500Name, rsaSize: Int = X509Utils.defaultKeySize("RSA"), dsaSize: Int = X509Utils.defaultKeySize("DSA"), curve: ECParameterSpec = X509Utils.defaultEllipticCurve(), issuer: Option[TLS.CertificateKey] = None, serial: BigInt = BigInt(1), notAfter: Instant = X509Utils.defaultExpire(), extensions: Set[CertExtension] = CertExtension.defaultExtensions()): TLS.KeySet = {
    val rsa = generate(subject, "RSA", rsaSize, issuer, serial, notAfter, extensions)
    val dsa = generate(subject, "DSA", dsaSize, issuer, serial, notAfter, extensions)
    val ecdsa = generateEcdsa(subject, curve, issuer, serial, notAfter, extensions)
    TLS.KeySet(Some(rsa), Some(dsa), Some(ecdsa))
  }
}
