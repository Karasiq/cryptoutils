package com.karasiq.tls.x509

import com.karasiq.tls.TLS
import com.karasiq.tls.TLS.Certificate
import com.karasiq.tls.x509.crl.CRL
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509CRLHolder

import scala.collection.concurrent.TrieMap

// TODO: OCSP
trait CertificateStatusProvider {
  def isRevoked(certificate: TLS.Certificate, issuer: TLS.Certificate): Boolean
}

object CertificateStatusProvider {
  def crl(): CertificateStatusProvider = new CRLOnlineCertificateStatusProvider()

  val alwaysValid = new CertificateStatusProvider {
    override def isRevoked(certificate: Certificate, issuer: Certificate): Boolean = false
  }
}

final class CRLOnlineCertificateStatusProvider extends CertificateStatusProvider {
  private val cache = TrieMap.empty[X500Name, Seq[X509CRLHolder]]

  private def loadCRL(certificate: Certificate): Seq[X509CRLHolder] = {
    cache.getOrElseUpdate(certificate.getIssuer, CRL.getRevocationLists(certificate))
  }

  override def isRevoked(certificate: Certificate, issuer: Certificate): Boolean = {
    loadCRL(certificate).exists(crl ⇒ CRL.verify(crl, issuer) && CRL.contains(crl, certificate))
  }
}