package com.karasiq.tls

import java.io.{FileInputStream, FileOutputStream, InputStream, OutputStream}
import java.security.KeyStore

import com.karasiq.tls.TLS.{Certificate, CertificateChain, CertificateKey, KeySet}
import com.karasiq.tls.TLSKeyStore.{CertificateEntry, KeyEntry}
import com.karasiq.tls.internal.BCConversions._
import com.typesafe.config.ConfigFactory
import org.apache.commons.io.IOUtils
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.{AsymmetricKeyParameter, DSAKeyParameters, ECKeyParameters, RSAKeyParameters}

import scala.collection.JavaConversions._
import scala.util.control.Exception

object TLSKeyStore {
  sealed trait Entry {
    def alias: String
  }

  sealed trait CertificateEntry extends Entry {
    def certificate: TLS.Certificate
    def chain: TLS.CertificateChain
  }

  sealed trait KeyEntry extends Entry with CertificateEntry {
    def keyPair(password: String = null): AsymmetricCipherKeyPair
  }

  def emptyKeyStore(): KeyStore = {
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    keyStore.load(null, null)
    keyStore
  }

  def keyStore(inputStream: InputStream, password: String): KeyStore = {
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    keyStore.load(inputStream, password.toCharArray)
    keyStore
  }

  def keyStore(path: String, password: String): KeyStore = {
    val inputStream = new FileInputStream(path)
    Exception.allCatch.andFinally(inputStream.close()) {
      keyStore(inputStream, password)
    }
  }

  def defaultKeyStore(): KeyStore = {
    val config = ConfigFactory.load().getConfig("karasiq.tls")
    this.keyStore(config.getString("key-store"), this.defaultPassword())
  }

  def defaultPassword(): String = {
    val config = ConfigFactory.load().getConfig("karasiq.tls")
    config.getString("key-store-pass")
  }

  def open(path: String, password: String): TLSKeyStore = {
    new TLSKeyStore(keyStore(path, password), password)
  }

  def empty(): TLSKeyStore = new TLSKeyStore(emptyKeyStore(), defaultPassword())

  def apply(): TLSKeyStore = new TLSKeyStore(defaultKeyStore(), defaultPassword())
}

/**
 * JCA keystore wrapper
 * @param keyStore JCA keystore
 * @param keyStorePass JCA keystore password
 */
class TLSKeyStore(keyStore: KeyStore = TLSKeyStore.defaultKeyStore(), keyStorePass: String = TLSKeyStore.defaultPassword()) {
  def contains(alias: String): Boolean = {
    keyStore.containsAlias(alias)
  }

  def delete(alias: String): Unit = {
    if (keyStore.containsAlias(alias)) {
      keyStore.deleteEntry(alias)
    }
  }

  def deleteKeySet(alias: String): Unit = {
    Seq("rsa", "dsa", "ecdsa").foreach { postfix ⇒
      delete(s"$alias-$postfix")
    }
  }

  def putKey(alias: String, key: TLS.CertificateKey, password: String = keyStorePass): Unit = {
    keyStore.setKeyEntry(alias, key.key.getPrivate.toPrivateKey, password.toCharArray, key.certificateChain.toJavaCertificateChain)
  }

  def putKeySet(alias: String, keySet: TLS.KeySet, password: String = keyStorePass): Unit = {
    if (keyStore.isKeyEntry(alias)) delete(alias)
    keySet.rsa.foreach(key ⇒ putKey(s"$alias-rsa", key, password))
    keySet.dsa.foreach(key ⇒ putKey(s"$alias-dsa", key, password))
    keySet.ecdsa.foreach(key ⇒ putKey(s"$alias-ecdsa", key, password))
  }

  def putCertificate(alias: String, certificate: TLS.Certificate): Unit = {
    keyStore.setCertificateEntry(alias, certificate.toJavaCertificate)
  }

  def getKey(alias: String, password: String = keyStorePass): AsymmetricCipherKeyPair = {
    val key = keyStore.getKey(alias, password.toCharArray)
    key.toAsymmetricCipherKeyPair(getCertificate(alias).getSubjectPublicKeyInfo)
  }

  def getCertificate(alias: String): TLS.Certificate = {
    keyStore.getCertificate(alias).toTlsCertificate
  }

  def getKeySet(alias: String, password: String = keyStorePass): TLS.KeySet = {
    def readKey[K <: AsymmetricKeyParameter](key: String)(implicit m: Manifest[K]): Option[CertificateKey] = {
      getEntry(key) match {
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
      readKey[K](s"$alias-$postfix").orElse(readKey[K](alias))
    }

    KeySet(autoSearch[RSAKeyParameters]("rsa"), autoSearch[DSAKeyParameters]("dsa"), autoSearch[ECKeyParameters]("ecdsa"))
  }

  def getCertificateChain(alias: String): TLS.CertificateChain = {
    new CertificateChain(keyStore.getCertificateChain(alias).map(_.toTlsCertificate))
  }

  def getEntry(alias: String): Option[TLSKeyStore.Entry] = {
    val pf: PartialFunction[String, TLSKeyStore.Entry] = {
      case a if keyStore.isKeyEntry(a) ⇒
        new KeyEntry {
          override def chain: CertificateChain = getCertificateChain(a)

          override def certificate: Certificate = getCertificate(a)

          override def keyPair(password: String): AsymmetricCipherKeyPair = {
            getKey(a, if (password == null) keyStorePass else password)
          }

          override def alias: String = a
        }

      case a if keyStore.isCertificateEntry(a) ⇒
        new CertificateEntry {
          override def chain: CertificateChain = getCertificateChain(a)

          override def certificate: Certificate = getCertificate(a)

          override def alias: String = a
        }
    }
    pf.lift(alias)
  }

  def iterator(): Iterator[TLSKeyStore.Entry] = {
    keyStore.aliases().toIterator.flatMap(getEntry)
  }

  def save(outputStream: OutputStream, password: String = keyStorePass): Unit = {
    keyStore.store(outputStream, password.toCharArray)
  }

  def saveAs(path: String, password: String = keyStorePass): Unit = {
    val outputStream = new FileOutputStream(path)
    Exception.allCatch.andFinally(IOUtils.closeQuietly(outputStream)) {
      save(outputStream, password)
    }
  }
}
