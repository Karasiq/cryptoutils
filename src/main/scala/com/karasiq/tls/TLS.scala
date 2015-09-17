package com.karasiq.tls

object TLS {
  type CertificateChain = org.bouncycastle.crypto.tls.Certificate
  type Certificate = org.bouncycastle.asn1.x509.Certificate
  type CertificateKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair

  case class CertificateKey(certificateChain: CertificateChain, key: CertificateKeyPair) {
    def certificate: TLS.Certificate = {
      import com.karasiq.tls.internal.BCConversions._
      certificateChain.toTlsCertificate
    }
  }

  case class KeySet(rsa: Option[CertificateKey] = None, dsa: Option[CertificateKey] = None, ecdsa: Option[CertificateKey] = None)
}
