package com.karasiq.tls

object TLS {
  type CertificateChain = org.bouncycastle.crypto.tls.Certificate
  type Certificate = org.bouncycastle.asn1.x509.Certificate
  type CertificateKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair

  case class CertificateKey(certificateChain: CertificateChain, key: CertificateKeyPair)

  case class KeySet(rsa: Option[CertificateKey] = None, dsa: Option[CertificateKey] = None, ecdsa: Option[CertificateKey] = None)

  object KeySet {
    def apply(keyStore: TLSKeyStore, name: String): KeySet = {
      def readKey(key: String): Option[CertificateKey] = {
        keyStore.getEntry(key).collect {
          case e: TLSKeyStore.KeyEntry ⇒
            CertificateKey(e.chain, e.keyPair())
        }
      }
      KeySet(readKey(s"$name-rsa").orElse(readKey(name)), readKey(s"$name-dsa"), readKey(s"$name-ecdsa"))
    }
  }
}
