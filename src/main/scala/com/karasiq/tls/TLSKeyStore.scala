package com.karasiq.tls

import java.io.{FileOutputStream, InputStream, OutputStream}
import java.security.KeyStore

import com.karasiq.tls.TLS.{Certificate, CertificateChain, CertificateKey, KeySet}
import com.karasiq.tls.TLSKeyStore.{CertificateEntry, KeyEntry}
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.ObjectLoader
import com.typesafe.config.ConfigFactory
import org.apache.commons.io.IOUtils
import org.bouncycastle.crypto.params.{AsymmetricKeyParameter, DSAKeyParameters, ECKeyParameters, RSAKeyParameters}

import scala.collection.JavaConversions._
import scala.util.control.Exception

/**
 * Key store loader class
 * @param password Key store encryption password
 * @param keyStoreType Key store type
 */
class KeyStoreLoader(password: String = null, keyStoreType: String = KeyStore.getDefaultType) extends ObjectLoader[KeyStore] {
  override def fromInputStream(inputStream: InputStream): KeyStore = {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(inputStream, Option(password).map(_.toCharArray).orNull)
    keyStore
  }
}

object TLSKeyStore {
  sealed trait Entry {
    def alias: String
  }

  sealed trait CertificateEntry extends Entry {
    def certificate: TLS.Certificate
    def chain: TLS.CertificateChain
  }

  sealed trait KeyEntry extends Entry with CertificateEntry {
    def keyPair(password: String = null): TLS.CertificateKeyPair
  }

  def emptyKeyStore(): KeyStore = new KeyStoreLoader().fromInputStream(null)

  def keyStore(inputStream: InputStream, password: String): KeyStore = {
    new KeyStoreLoader(password).fromInputStream(inputStream)
  }

  def keyStore(path: String, password: String): KeyStore = {
    new KeyStoreLoader(password).fromFile(path)
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
 * @param password JCA keystore password
 */
class TLSKeyStore(val keyStore: KeyStore = TLSKeyStore.defaultKeyStore(), val password: String = TLSKeyStore.defaultPassword()) {
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

  def putKey(alias: String, key: TLS.CertificateKey, password: String = password): Unit = {
    keyStore.setKeyEntry(alias, key.key.getPrivate.toPrivateKey, password.toCharArray, key.certificateChain.toJavaCertificateChain)
  }

  def putKeySet(alias: String, keySet: TLS.KeySet, password: String = password): Unit = {
    if (keyStore.isKeyEntry(alias)) delete(alias)
    keySet.rsa.foreach(key ⇒ putKey(s"$alias-rsa", key, password))
    keySet.dsa.foreach(key ⇒ putKey(s"$alias-dsa", key, password))
    keySet.ecdsa.foreach(key ⇒ putKey(s"$alias-ecdsa", key, password))
  }

  def putCertificate(alias: String, certificate: TLS.Certificate): Unit = {
    keyStore.setCertificateEntry(alias, certificate.toJavaCertificate)
  }

  def getKey(alias: String, password: String = password): TLS.CertificateKeyPair = {
    val key = keyStore.getKey(alias, password.toCharArray)
    key.toAsymmetricCipherKeyPair(getCertificate(alias).getSubjectPublicKeyInfo)
  }

  def getCertificate(alias: String): TLS.Certificate = {
    keyStore.getCertificate(alias).toTlsCertificate
  }

  def getKeySet(alias: String, password: String = password): TLS.KeySet = {
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

          override def keyPair(password: String): TLS.CertificateKeyPair = {
            getKey(a, if (password == null) password else password)
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

  def save(outputStream: OutputStream, password: String = password): Unit = {
    keyStore.store(outputStream, password.toCharArray)
  }

  def saveAs(path: String, password: String = password): Unit = {
    val outputStream = new FileOutputStream(path)
    Exception.allCatch.andFinally(IOUtils.closeQuietly(outputStream)) {
      save(outputStream, password)
    }
  }
}
