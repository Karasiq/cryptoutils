package com.karasiq.tls.internal

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}

import com.karasiq.tls.TLS
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.x509.{AlgorithmIdentifier, SubjectPublicKeyInfo}
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.{AsymmetricKeyParameter, DSAKeyParameters, ECKeyParameters, RSAKeyParameters}
import org.bouncycastle.crypto.tls.CipherSuite
import org.bouncycastle.crypto.util.{PrivateKeyFactory, PrivateKeyInfoFactory, PublicKeyFactory, SubjectPublicKeyInfoFactory}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder

import scala.util.Try
import scala.util.control.Exception

/**
 * Provides conversions between JCA and BouncyCastle classes
 */
object BCConversions {
  private val provider = new BouncyCastleProvider

  implicit class JavaKeyOps(key: java.security.Key) {
    private def convertPKCS8Key(data: Array[Byte], public: SubjectPublicKeyInfo): AsymmetricCipherKeyPair = {
      new AsymmetricCipherKeyPair(PublicKeyFactory.createKey(public), PrivateKeyFactory.createKey(data))
    }

//    private def convertRsaKey(rsa: RSAPrivateCrtKey): AsymmetricCipherKeyPair = {
//      val publicParameters = new RSAKeyParameters(false, rsa.getModulus, rsa.getPublicExponent)
//      val privateParameters = new RSAPrivateCrtKeyParameters(rsa.getModulus, rsa.getPublicExponent,
//        rsa.getPrivateExponent, rsa.getPrimeP, rsa.getPrimeQ, rsa.getPrimeExponentP, rsa.getPrimeExponentQ, rsa.getCrtCoefficient)
//      new AsymmetricCipherKeyPair(publicParameters, privateParameters)
//    }

    def toAsymmetricCipherKeyPair(public: SubjectPublicKeyInfo): AsymmetricCipherKeyPair = key match {
      // case rsa: java.security.interfaces.RSAPrivateCrtKey ⇒
      //  convertRsaKey(rsa)

      case privateKey: java.security.PrivateKey ⇒
        convertPKCS8Key(privateKey.getEncoded, public)

      case _ ⇒
        throw new IllegalArgumentException(s"Not supported: ${public.getClass}")
    }

    def toSubjectPublicKeyInfo: SubjectPublicKeyInfo = {
      SubjectPublicKeyInfo.getInstance(key.getEncoded)
    }
  }

  implicit class SubjectPublicKeyInfoOps(subjectPublicKeyInfo: SubjectPublicKeyInfo) {
    def toPublicKey: java.security.PublicKey = {
      PublicKeyFactory.createKey(subjectPublicKeyInfo).toPublicKey
    }
  }

  implicit class JavaKeyPairOps(keyPair: java.security.KeyPair) {
    def toAsymmetricCipherKeyPair: AsymmetricCipherKeyPair = {
      keyPair.getPrivate.toAsymmetricCipherKeyPair(keyPair.getPublic.toSubjectPublicKeyInfo)
    }
  }

  implicit class AsymmetricCipherKeyPairOps(keyPair: AsymmetricCipherKeyPair) {
    def toKeyPair: java.security.KeyPair = {
      new java.security.KeyPair(keyPair.getPublic.toPublicKey, keyPair.getPrivate.toPrivateKey)
    }
  }

  implicit class AsymmetricKeyParameterOps(key: AsymmetricKeyParameter) {
    def algorithm(): String = {
      key match {
        case _: ECKeyParameters ⇒
          "ECDSA"

        case _: RSAKeyParameters ⇒
          "RSA"

        case _: DSAKeyParameters ⇒
          "DSA"

        case _ ⇒
          throw new IllegalArgumentException(s"Unknown key algorithm: ${key.getClass}")
      }
    }

    def toSubjectPublicKeyInfo: SubjectPublicKeyInfo = {
      toPublicKey.toSubjectPublicKeyInfo
    }

    def toPrivateKey: PrivateKey = {
      val keyGenerator = KeyFactory.getInstance(this.algorithm(), provider)
      keyGenerator.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(key).getEncoded))
    }

    def toPublicKey: PublicKey = {
      val keyGenerator = KeyFactory.getInstance(this.algorithm(), provider)
      keyGenerator.generatePublic(new X509EncodedKeySpec(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key).getEncoded))
    }
  }

  implicit class JavaCertificateOps(certificate: java.security.cert.Certificate) {
    def toTlsCertificate: TLS.Certificate = {
      org.bouncycastle.asn1.x509.Certificate.getInstance(certificate.getEncoded)
    }

    def toTlsCertificateChain: TLS.CertificateChain = {
      toTlsCertificate.toTlsCertificateChain
    }
  }

  implicit class CertificateOps(certificate: TLS.Certificate) {
    def toTlsCertificateChain: TLS.CertificateChain = {
      new TLS.CertificateChain(Array(certificate))
    }

    def toJavaCertificate: java.security.cert.Certificate = {
      val certificateFactory = CertificateFactory.getInstance("X.509")
      val inputStream = new ByteArrayInputStream(certificate.getEncoded)
      Exception.allCatch.andFinally(IOUtils.closeQuietly(inputStream)) {
        certificateFactory.generateCertificate(inputStream)
      }
    }
  }

  implicit class CertificateChainOps(chain: TLS.CertificateChain) {
    def toTlsCertificate: TLS.Certificate = {
      chain.getCertificateList.headOption
        .getOrElse(throw new NoSuchElementException("Empty certificate chain"))
    }

    def toJavaCertificateChain: Array[java.security.cert.Certificate] = {
      chain.getCertificateList.map(_.toJavaCertificate)
    }
  }

  object DigestAlgorithm {
    def apply(name: String): AlgorithmIdentifier = {
      val finder = new DefaultDigestAlgorithmIdentifierFinder()
      Option(finder.find(name))
        .getOrElse(throw new IllegalArgumentException(s"Invalid digest identifier: $name"))
    }
  }

  object SignatureDigestAlgorithm {
    def apply(keyAlg: String, hashAlg: String): String = {
      s"${hashAlg.replace("-", "").toUpperCase}with${keyAlg.toUpperCase}"
    }
  }

  object CipherSuiteId {
    def apply(cs: String): Int = {
      Try(classOf[CipherSuite].getField(cs).getInt(null))
        .getOrElse(throw new IllegalArgumentException(s"Invalid cipher suite: $cs"))
    }

    def asString(cs: Int): String = {
      val fields = classOf[CipherSuite].getFields
      fields
        .find(f ⇒ f.getType == Integer.TYPE && f.getInt(null) == cs)
        .fold(throw new IllegalArgumentException(s"Unknown cipher suite: $cs"))(_.getName)
    }
  }
}
