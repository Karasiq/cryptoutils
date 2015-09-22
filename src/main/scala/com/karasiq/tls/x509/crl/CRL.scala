package com.karasiq.tls.x509.crl

import java.math.BigInteger
import java.net.URL
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.Date
import java.util.concurrent.TimeUnit

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.x509.X509Utils
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.{X509CRLHolder, X509CertificateHolder, X509v2CRLBuilder}

import scala.util.control.Exception

object CRL {
  private val config = ConfigFactory.load().getConfig("karasiq.tls.crl-defaults")

  def defaultNextUpdate(): Instant = {
    Instant.now().plus(config.getDuration("next-update-in", TimeUnit.SECONDS), ChronoUnit.SECONDS)
  }

  sealed trait Revoked

  case class RevokedSerial(serial: BigInt, reason: Int = CRLReason.unspecified, revocationDate: Instant = Instant.now()) extends Revoked
  case class RevokedCert(cert: TLS.Certificate, reason: Int = CRLReason.unspecified, revocationDate: Instant = Instant.now()) extends Revoked
  case class RevokedCerts(crl: X509CRLHolder) extends Revoked

  def build(issuer: TLS.CertificateKey, revoked: Seq[Revoked], nextUpdate: Instant = defaultNextUpdate()): X509CRLHolder = {
    val builder = new X509v2CRLBuilder(issuer.certificate.getSubject, new Date())
    val extensionUtils = X509Utils.extensionUtils(config.getString("key-id-algorithm"))
    val contentSigner = X509Utils.contentSigner(issuer.key.getPrivate.toPrivateKey, config.getString("sign-algorithm"))

    builder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(new X509CertificateHolder(issuer.certificate)))
    builder.setNextUpdate(Date.from(nextUpdate))

    def addSerial(serial: BigInteger, reason: Int, revocationDate: Instant) = {
      val extGen = new ExtensionsGenerator()
      extGen.addExtension(Extension.reasonCode, false, CRLReason.lookup(reason))
      extGen.addExtension(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(issuer.certificate.getSubject)))
      builder.addCRLEntry(serial, Date.from(revocationDate), extGen.generate())
    }

    revoked.foreach {
      case RevokedCerts(crl) ⇒
        builder.addCRL(crl)

      case RevokedCert(cert, reason, revocationDate) ⇒
        addSerial(cert.getSerialNumber.getValue, reason, revocationDate)

      case RevokedSerial(serial, reason, revocationDate) ⇒
        addSerial(serial.underlying(), reason, revocationDate)
    }

    builder.build(contentSigner)
  }

  def verify(crl: X509CRLHolder, issuer: TLS.Certificate): Boolean = {
    val verifier = X509Utils.contentVerifierProvider(issuer)
    X509Utils.isKeyUsageAllowed(issuer, KeyUsage.cRLSign) && crl.isSignatureValid(verifier)
  }

  def contains(crl: X509CRLHolder, cert: TLS.Certificate): Boolean = {
    crl.getRevokedCertificate(cert.getSerialNumber.getValue) != null
  }

  def fromUrl(url: String): X509CRLHolder = {
    val inputStream = new URL(url).openStream()
    Exception.allCatch.andFinally(inputStream.close()) {
      new X509CRLHolder(inputStream)
    }
  }

  def getRevocationLists(cert: TLS.Certificate): Seq[X509CRLHolder] = {
    val urls = X509Utils.getCrlDistributionUrls(cert)
    urls.map(fromUrl)
  }
}
