package com.karasiq.tls.internal

import com.karasiq.tls.{TLS, TLSKeyStore}
import com.typesafe.config.{Config, ConfigFactory}
import org.bouncycastle.crypto.params._
import org.bouncycastle.crypto.tls._

import scala.collection.GenTraversableOnce
import scala.collection.JavaConversions._
import scala.util.Try

object TLSUtils {
  private def openConfig(): Config = ConfigFactory.load().getConfig("karasiq.tls")

  def signatureAlgorithm(key: AsymmetricKeyParameter): SignatureAndHashAlgorithm = {
    val config = openConfig()
    val hash: Short = {
      val name = config.getString("hash-algorithm")
      Try(classOf[HashAlgorithm].getField(name.replace("-", "").toLowerCase).getShort(null))
        .getOrElse(throw new IllegalArgumentException("Invalid hash algorithm: " + name))
    }

    val sign: Short = key match {
      case _: RSAKeyParameters ⇒
        SignatureAlgorithm.rsa

      case _: ECKeyParameters ⇒
        SignatureAlgorithm.ecdsa

      case _: DSAKeyParameters ⇒
        SignatureAlgorithm.dsa

      case _ ⇒
        SignatureAlgorithm.anonymous
    }

    new SignatureAndHashAlgorithm(hash, sign)
  }

  def defaultSignatureAlgorithms(protocolVersion: ProtocolVersion): java.util.Vector[_] = {
    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(protocolVersion)) {
      TlsUtils.getDefaultSupportedSignatureAlgorithms
    } else {
      null
    }
  }

  def authoritiesOf(trustStore: TLSKeyStore): java.util.Vector[_] = {
    @inline
    def asJavaVector(data: GenTraversableOnce[AnyRef]): java.util.Vector[AnyRef] = {
      val vector = new java.util.Vector[AnyRef]()
      data.foreach(vector.add)
      vector
    }

    asJavaVector(trustStore.iterator().collect {
      case cert: TLSKeyStore.CertificateEntry ⇒
        cert.certificate.getSubject
    })
  }

  def certificateRequest(protocolVersion: ProtocolVersion, trustStore: TLSKeyStore): CertificateRequest = {
    val certificateTypes = Array(ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign)
    new CertificateRequest(certificateTypes, defaultSignatureAlgorithms(protocolVersion), authoritiesOf(trustStore))
  }

  def isInAuthorities(chain: TLS.CertificateChain, certificateRequest: CertificateRequest): Boolean = {
    chain.getCertificateList.exists { cert ⇒
      certificateRequest.getCertificateAuthorities.contains(cert.getSubject) || certificateRequest.getCertificateAuthorities.contains(cert.getIssuer)
    }
  }

  /**
   * Loads cipher suites from config
   * @return BC cipher suites array
   */
  def defaultCipherSuites(): Array[Int] = {
    val config = openConfig()
    val cipherSuites = config.getStringList("cipher-suites").flatMap { cs ⇒
      Try(classOf[CipherSuite].getField(cs).getInt(null)).toOption
    }
    require(cipherSuites.nonEmpty, "Cipher suites is empty")
    cipherSuites.toArray
  }

  private def readVersion(v: String): ProtocolVersion = v match {
    case "TLSv1" ⇒
      ProtocolVersion.TLSv10

    case "TLSv1.1" ⇒
      ProtocolVersion.TLSv11

    case "TLSv1.2" ⇒
      ProtocolVersion.TLSv12

    case _ ⇒
      throw new IllegalArgumentException("Invalid TLS version: " + v)
  }

  def minVersion(): ProtocolVersion = {
    val config = openConfig()
    readVersion(config.getString("min-version"))
  }

  def maxVersion(): ProtocolVersion = {
    val config = openConfig()
    readVersion(config.getString("max-version"))
  }
}
