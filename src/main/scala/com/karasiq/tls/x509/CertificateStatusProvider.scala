package com.karasiq.tls.x509

import com.karasiq.tls.TLS
import com.karasiq.tls.TLS.Certificate
import com.karasiq.tls.x509.crl.CRL
import com.karasiq.tls.x509.ocsp.OCSP
import org.bouncycastle.cert.X509CRLHolder

import scala.collection.concurrent.TrieMap

/**
 * Certificate revocation status provider trait
 */
trait CertificateStatusProvider {
  /**
   * Is certificate revoked
   * @param certificate Certificate
   * @param issuer Issuer certificate
   * @return Is certificate revoked
   */
  def isRevoked(certificate: TLS.Certificate, issuer: TLS.Certificate): Boolean
}

object CertificateStatusProvider {
  /**
   * CRL-based certificate status provider
   * @note Uses internet for verification
   */
  val CRL: CertificateStatusProvider = new CRLOnlineCertificateStatusProvider()

  /**
   * OCSP-based certificate status provider
   * @note Uses internet for verification
   */
  val OCSP: CertificateStatusProvider = new OCSPOnlineCertificateStatusProvider()

  /**
   * Always valid certificate status provider
   */
  object AlwaysValid extends CertificateStatusProvider {
    override def isRevoked(certificate: Certificate, issuer: Certificate): Boolean = false
  }
}

final class CRLOnlineCertificateStatusProvider extends CertificateStatusProvider {
  private val cache = TrieMap.empty[(Seq[String], Certificate), Seq[X509CRLHolder]]

  private def loadCRL(certificate: Certificate, issuer: Certificate): Seq[X509CRLHolder] = {
    cache.getOrElseUpdate(X509Utils.getCrlDistributionUrls(issuer) → issuer, CRL.getRevocationLists(certificate, issuer))
  }

  override def isRevoked(certificate: Certificate, issuer: Certificate): Boolean = {
    loadCRL(certificate, issuer).exists(crl ⇒ CRL.verify(crl, issuer) && CRL.contains(crl, certificate))
  }
}

final class OCSPOnlineCertificateStatusProvider extends CertificateStatusProvider {
  private val cache = TrieMap.empty[Certificate, Option[OCSP.Status]]

  private def loadOCSP(certificate: Certificate, issuer: Certificate): Option[OCSP.Status] = {
    cache.getOrElseUpdate(certificate, OCSP.getStatus(certificate, issuer))
  }

  override def isRevoked(certificate: Certificate, issuer: Certificate): Boolean = {
    loadOCSP(certificate, issuer).exists(_.isRevoked)
  }
}