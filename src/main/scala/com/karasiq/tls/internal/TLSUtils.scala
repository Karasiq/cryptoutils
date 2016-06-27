package com.karasiq.tls.internal

import java.security.Provider

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions.CipherSuiteId
import com.karasiq.tls.x509.CertificateVerifier
import com.typesafe.config.ConfigFactory
import org.bouncycastle.crypto.params._
import org.bouncycastle.crypto.tls._
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec

import scala.collection.GenTraversableOnce
import scala.collection.JavaConversions._
import scala.util.Try

object TLSUtils {
  private[tls] val provider: Provider = new BouncyCastleProvider

  private val config = ConfigFactory.load().getConfig("karasiq.tls")

  def signatureAlgorithm(key: AsymmetricKeyParameter, hashAlgorithm: String = defaultHashAlgorithm()): SignatureAndHashAlgorithm = {
    val hash: Short = {
      Try(classOf[HashAlgorithm].getField(hashAlgorithm.replace("-", "").toLowerCase).getShort(null))
        .getOrElse(throw new IllegalArgumentException(s"Invalid hash algorithm: $hashAlgorithm"))
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

  private def authoritiesOf(trustStore: CertificateVerifier): java.util.Vector[_] = {
    @inline
    def asJavaVector(data: GenTraversableOnce[AnyRef]): java.util.Vector[AnyRef] = {
      val vector = new java.util.Vector[AnyRef]()
      data.foreach(vector.add)
      vector
    }

    asJavaVector(trustStore.trustedRootCertificates.map(_.getSubject))
  }

  def certificateRequest(protocolVersion: ProtocolVersion, verifier: CertificateVerifier): CertificateRequest = {
    val certificateTypes = Array(ClientCertificateType.rsa_sign, ClientCertificateType.ecdsa_sign, ClientCertificateType.dss_sign)
    new CertificateRequest(certificateTypes, defaultSignatureAlgorithms(protocolVersion), authoritiesOf(verifier))
  }

  def certificateFor(keySet: TLS.KeySet, certificateRequest: CertificateRequest): Option[TLS.CertificateKey] = {
    val keys = certificateRequest.getCertificateTypes.flatMap {
      case ClientCertificateType.ecdsa_sign ⇒
        keySet.ecdsa

      case ClientCertificateType.rsa_sign ⇒
        keySet.rsa

      case ClientCertificateType.dss_sign ⇒
        keySet.dsa
    }

    keys.find(key ⇒ isInAuthorities(key.certificateChain, certificateRequest))
  }

  def isInAuthorities(chain: TLS.CertificateChain, certificateRequest: CertificateRequest): Boolean = {
    chain.getCertificateList.exists { cert ⇒
      certificateRequest.getCertificateAuthorities.contains(cert.getSubject) || certificateRequest.getCertificateAuthorities.contains(cert.getIssuer)
    }
  }

  private def asProtocolVersion(string: String): ProtocolVersion = string match {
    case "SSLv3" ⇒
      ProtocolVersion.SSLv3

    case "TLSv1" | "TLSv1.0" ⇒
      ProtocolVersion.TLSv10

    case "TLSv1.1" ⇒
      ProtocolVersion.TLSv11

    case "TLSv1.2" ⇒
      ProtocolVersion.TLSv12

    case "DTLSv1" | "DTLSv1.0" ⇒
      ProtocolVersion.DTLSv10

    case "DTLSv1.2" ⇒
      ProtocolVersion.DTLSv12

    case _ ⇒
      throw new IllegalArgumentException("Invalid TLS version: " + string)
  }

  /**
    * Loads cipher suites from config
    * @return BC cipher suites array
    */
  def defaultCipherSuites(): Array[Int] = {
    config.getStringList("cipher-suites")
      .map(CipherSuiteId(_))
      .ensuring(_.nonEmpty, "Cipher suites is empty")
      .toArray
  }

  def defaultHashAlgorithm(): String = {
    config.getString("hash-algorithm")
  }

  def defaultSignatureAlgorithms(protocolVersion: ProtocolVersion): java.util.Vector[_] = {
    if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(protocolVersion)) {
      TlsUtils.getDefaultSupportedSignatureAlgorithms
    } else {
      null
    }
  }

  def minVersion(): ProtocolVersion = {
    asProtocolVersion(config.getString("min-version"))
  }

  def maxVersion(): ProtocolVersion = {
    asProtocolVersion(config.getString("max-version"))
  }

  def getEllipticCurve(name: String): ECParameterSpec = {
    Option(ECNamedCurveTable.getParameterSpec(name))
      .getOrElse(throw new IllegalArgumentException(s"Elliptic curve not defined: $name"))
  }
}
