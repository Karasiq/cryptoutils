package com.karasiq.tls

import org.bouncycastle.crypto.params.{AsymmetricKeyParameter, DSAKeyParameters, ECKeyParameters, RSAKeyParameters}

object TLS {
  type CertificateChain = org.bouncycastle.crypto.tls.Certificate
  type Certificate = org.bouncycastle.asn1.x509.Certificate
  type CertificateKeyPair = org.bouncycastle.crypto.AsymmetricCipherKeyPair

  case class CertificateKey(certificateChain: CertificateChain, key: CertificateKeyPair)

  case class KeySet(rsa: Option[CertificateKey] = None, dsa: Option[CertificateKey] = None, ecdsa: Option[CertificateKey] = None)

  object KeySet {
    def apply(keyStore: TLSKeyStore, name: String, password: String): KeySet = {
      def readKey[K <: AsymmetricKeyParameter](key: String)(implicit m: Manifest[K]): Option[CertificateKey] = {
        keyStore.getEntry(key).collect {
          case e: TLSKeyStore.KeyEntry ⇒
            val key = e.keyPair(password)
            if (!m.runtimeClass.isAssignableFrom(key.getPrivate.getClass)) {
              throw new IllegalArgumentException(s"Invalid key type: ${key.getPrivate.getClass.getSimpleName} (${m.runtimeClass.getSimpleName} expected)")
            }
            CertificateKey(e.chain, key)
        }
      }
      KeySet(readKey[RSAKeyParameters](s"$name-rsa").orElse(readKey[RSAKeyParameters](name)), readKey[DSAKeyParameters](s"$name-dsa"), readKey[ECKeyParameters](s"$name-ecdsa"))
    }

    def apply(keyStore: TLSKeyStore, name: String): KeySet = apply(keyStore, name, null)
  }
}
