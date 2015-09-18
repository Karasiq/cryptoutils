package com.karasiq.tls.internal

import java.security.Provider

import com.karasiq.tls.TLS
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
  private[tls] lazy val provider: Provider = new BouncyCastleProvider

  private val config = ConfigFactory.load().getConfig("karasiq.tls")

  def signatureAlgorithm(key: AsymmetricKeyParameter): SignatureAndHashAlgorithm = {
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

  def authoritiesOf(trustStore: CertificateVerifier): java.util.Vector[_] = {
    @inline
    def asJavaVector(data: GenTraversableOnce[AnyRef]): java.util.Vector[AnyRef] = {
      val vector = new java.util.Vector[AnyRef]()
      data.foreach(vector.add)
      vector
    }

    asJavaVector(trustStore.trustedRootCertificates.map(_.getSubject))
  }

  def certificateRequest(protocolVersion: ProtocolVersion, verifier: CertificateVerifier): CertificateRequest = {
    val certificateTypes = Array(ClientCertificateType.rsa_sign, ClientCertificateType.dss_sign, ClientCertificateType.ecdsa_sign)
    new CertificateRequest(certificateTypes, defaultSignatureAlgorithms(protocolVersion), authoritiesOf(verifier))
  }

  def certificateFor(keySet: TLS.KeySet, certificateRequest: CertificateRequest): Option[TLS.CertificateKey] = {
    val types = certificateRequest.getCertificateTypes.toSet
    keySet.ecdsa.filter(c ⇒ types.contains(ClientCertificateType.ecdsa_sign) && isInAuthorities(c.certificateChain, certificateRequest))
      .orElse(keySet.rsa.filter(c ⇒ types.contains(ClientCertificateType.rsa_sign) && isInAuthorities(c.certificateChain, certificateRequest)))
      .orElse(keySet.dsa.filter(c ⇒ types.contains(ClientCertificateType.dss_sign) && isInAuthorities(c.certificateChain, certificateRequest)))
  }

  def isInAuthorities(chain: TLS.CertificateChain, certificateRequest: CertificateRequest): Boolean = {
    chain.getCertificateList.exists { cert ⇒
      certificateRequest.getCertificateAuthorities.contains(cert.getSubject) || certificateRequest.getCertificateAuthorities.contains(cert.getIssuer)
    }
  }

  def stringAsCipherSuite(cs: String): Int = {
    Try(classOf[CipherSuite].getField(cs).getInt(null))
      .getOrElse(throw new IllegalArgumentException("Invalid cipher suite: " + cs))
  }

  def cipherSuiteAsString(cs: Int): String = {
    val fields = classOf[CipherSuite].getFields
    fields
      .find(f ⇒ f.getType == Integer.TYPE && f.getInt(null) == cs)
      .fold(throw new IllegalArgumentException("Unknown cipher suite: " + cs))(_.getName)
  }

  /**
   * Loads cipher suites from config
   * @return BC cipher suites array
   */
  def defaultCipherSuites(): Array[Int] = {
    val cipherSuites = config.getStringList("cipher-suites").map(stringAsCipherSuite)
    require(cipherSuites.nonEmpty, "Cipher suites is empty")
    cipherSuites.toArray
  }

  private def asProtocolVersion(v: String): ProtocolVersion = v match {
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
    asProtocolVersion(config.getString("min-version"))
  }

  def maxVersion(): ProtocolVersion = {
    asProtocolVersion(config.getString("max-version"))
  }

  def getEllipticCurve(name: String): ECParameterSpec = {
    Option(ECNamedCurveTable.getParameterSpec(name))
      .getOrElse(throw new IllegalArgumentException("Elliptic curve not defined: " + name))
  }
}
