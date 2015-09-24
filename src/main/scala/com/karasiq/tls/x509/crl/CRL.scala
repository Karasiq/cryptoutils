package com.karasiq.tls.x509.crl

import java.io.InputStream
import java.math.BigInteger
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.concurrent.TimeUnit

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.ObjectLoader
import com.karasiq.tls.x509.X509Utils
import com.karasiq.tls.x509.crl.CRLHolder.{Revoked, RevokedCert, RevokedCerts, RevokedSerial}
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.{X509CRLHolder, X509CertificateHolder, X509v2CRLBuilder}

object CRLHolder {
  sealed trait Revoked

  case class RevokedSerial(serial: BigInt, reason: Int = CRLReason.unspecified, revocationDate: Instant = Instant.now()) extends Revoked
  case class RevokedCert(cert: TLS.Certificate, reason: Int = CRLReason.unspecified, revocationDate: Instant = Instant.now()) extends Revoked
  case class RevokedCerts(crl: X509CRLHolder) extends Revoked
}

trait CRLBuilder {
  /**
   * Creates certificate revocation list
   * @param issuer CRL issuer credentials
   * @param revoked Revoked certificates
   * @param nextUpdate Next CRL availability time
   * @return Certificate revocation list
   */
  def build(issuer: TLS.CertificateKey, revoked: Seq[Revoked], nextUpdate: Instant): X509CRLHolder
}

trait CRLReader extends ObjectLoader[X509CRLHolder] {
  override def fromInputStream(inputStream: InputStream): X509CRLHolder = {
    new X509CRLHolder(inputStream)
  }

  /**
   * Verifies CRL signature
   * @param crl Certificate revocation list
   * @param issuer CRL issuer certificate
   * @return Is signature valid
   */
  def verify(crl: X509CRLHolder, issuer: TLS.Certificate): Boolean = {
    X509Utils.isKeyUsageAllowed(issuer, KeyUsage.cRLSign) && crl.isSignatureValid(X509Utils.contentVerifierProvider(issuer))
  }

  /**
   * Checks if CRL contains certificate
   * @param crl Certificate revocation list
   * @param cert Certificate
   * @return Is certificate revoked
   */
  def contains(crl: X509CRLHolder, cert: TLS.Certificate): Boolean = {
    crl.getRevokedCertificate(cert.getSerialNumber.getValue) != null
  }

  /**
   * Tries to load revocation lists for provided certificate
   * @param cert Certificate
   * @param issuer CRL issuer
   * @return Certificate revocation lists
   */
  def getRevocationLists(cert: TLS.Certificate, issuer: TLS.Certificate): Seq[X509CRLHolder] = {
    val urls = X509Utils.getCrlDistributionUrls(cert)
    urls.map(fromURL).filter(verify(_, issuer))
  }
}

/**
 * Certificate revocation list utility
 * @see [[https://en.wikipedia.org/wiki/Revocation_list]]
 */
object CRL extends CRLBuilder with CRLReader {
  private val config = ConfigFactory.load().getConfig("karasiq.tls.crl-defaults")

  def defaultKeyIdAlgorithm(): String = {
    config.getString("key-id-algorithm")
  }

  def defaultSignAlgorithm(): String = {
    config.getString("sign-algorithm")
  }

  def defaultNextUpdate(): Instant = {
    Instant.now().plus(config.getDuration("next-update-in", TimeUnit.SECONDS), ChronoUnit.SECONDS)
  }

  private def addSerial(builder: X509v2CRLBuilder, issuer: TLS.CertificateKey, serial: BigInteger, reason: Int, revocationDate: Instant) = {
    val extGen = new ExtensionsGenerator()
    extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(reason))
    extGen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(issuer.certificate.getSubject)))
    builder.addCRLEntry(serial, Date.from(revocationDate), extGen.generate())
  }
  
  def build(issuer: TLS.CertificateKey, revoked: Seq[Revoked], nextUpdate: Instant = defaultNextUpdate()): X509CRLHolder = {
    assert(X509Utils.isKeyUsageAllowed(issuer.certificate, KeyUsage.cRLSign), "CRL signing not allowed")

    val builder = new X509v2CRLBuilder(issuer.certificate.getSubject, new Date())
    val extensionUtils = X509Utils.extensionUtils(defaultKeyIdAlgorithm())
    val contentSigner = X509Utils.contentSigner(issuer.key.getPrivate.toPrivateKey, defaultSignAlgorithm())

    builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(issuer.certificate)))
    builder.setNextUpdate(Date.from(nextUpdate))

    revoked.foreach {
      case RevokedCerts(crl) ⇒
        builder.addCRL(crl)

      case RevokedCert(cert, reason, revocationDate) ⇒
        addSerial(builder, issuer, cert.getSerialNumber.getValue, reason, revocationDate)

      case RevokedSerial(serial, reason, revocationDate) ⇒
        addSerial(builder, issuer, serial.underlying(), reason, revocationDate)
    }

    builder.build(contentSigner)
  }


}
