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
        keyStore.getEntry(key) match {
          case Some(e: TLSKeyStore.KeyEntry) ⇒
            val key = e.keyPair(password)
            if (m.runtimeClass.isAssignableFrom(key.getPrivate.getClass)) {
              Some(CertificateKey(e.chain, key))
            } else {
              None
            }

          case _ ⇒
            None
        }
      }

      def autoSearch[K <: AsymmetricKeyParameter](postfix: String)(implicit m: Manifest[K]) = {
        readKey[K](s"$name-$postfix").orElse(readKey[K](name))
      }

      KeySet(autoSearch[RSAKeyParameters]("rsa"), autoSearch[DSAKeyParameters]("dsa"), autoSearch[ECKeyParameters]("ecdsa"))
    }

    def apply(keyStore: TLSKeyStore, name: String): KeySet = apply(keyStore, name, null)
  }
}
