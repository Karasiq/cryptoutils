package com.karasiq.tls.internal

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.spec.{PKCS8EncodedKeySpec, X509EncodedKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey}

import com.karasiq.tls.TLS
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.{AlgorithmIdentifier, SubjectPublicKeyInfo}
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.{AsymmetricKeyParameter, DSAKeyParameters, ECKeyParameters, RSAKeyParameters}
import org.bouncycastle.crypto.tls.CipherSuite
import org.bouncycastle.crypto.util.{PrivateKeyFactory, PrivateKeyInfoFactory, PublicKeyFactory, SubjectPublicKeyInfoFactory}
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder

import scala.util.Try

/**
 * Provides conversions between JCA and BouncyCastle classes
 */
object BCConversions {
  implicit class JavaKeyOps(private val key: java.security.Key) extends AnyVal {
    private def convertPKCS8Key(data: Array[Byte], public: SubjectPublicKeyInfo): AsymmetricCipherKeyPair = {
      new AsymmetricCipherKeyPair(PublicKeyFactory.createKey(public), PrivateKeyFactory.createKey(data))
    }

    def toAsymmetricCipherKeyPair(public: SubjectPublicKeyInfo): AsymmetricCipherKeyPair = key match {
      case privateKey: java.security.PrivateKey ⇒
        convertPKCS8Key(privateKey.getEncoded, public)

      case _ ⇒
        throw new IllegalArgumentException(s"Not supported: ${key.getClass}")
    }

    def toAsymmetricKeyParameter: AsymmetricKeyParameter = key match {
      case privateKey: java.security.PrivateKey ⇒
        PrivateKeyFactory.createKey(key.getEncoded)

      case publicKey: java.security.PublicKey ⇒
        PublicKeyFactory.createKey(key.getEncoded)

      case _ ⇒
        throw new IllegalArgumentException(s"Not supported: ${key.getClass}")
    }

    def toSubjectPublicKeyInfo: SubjectPublicKeyInfo = {
      SubjectPublicKeyInfo.getInstance(key.getEncoded)
    }

    def toPrivateKeyInfo: PrivateKeyInfo = {
      PrivateKeyInfoFactory.createPrivateKeyInfo(toAsymmetricKeyParameter)
    }
  }

  implicit class SubjectPublicKeyInfoOps(private val key: SubjectPublicKeyInfo) extends AnyVal {
    def toAsymmetricKeyParameter: AsymmetricKeyParameter = {
      PublicKeyFactory.createKey(key)
    }

    def toPublicKey: java.security.PublicKey = {
      toAsymmetricKeyParameter.toPublicKey
    }
  }

  implicit class PrivateKeyInfoOps(private val key: PrivateKeyInfo) extends AnyVal {
    def toAsymmetricKeyParameter: AsymmetricKeyParameter = {
      PrivateKeyFactory.createKey(key)
    }

    def toPrivateKey: PrivateKey = {
      toAsymmetricKeyParameter.toPrivateKey
    }
  }

  implicit class JavaKeyPairOps(private val pair: java.security.KeyPair) extends AnyVal {
    def toAsymmetricCipherKeyPair: AsymmetricCipherKeyPair = {
      pair.getPrivate.toAsymmetricCipherKeyPair(pair.getPublic.toSubjectPublicKeyInfo)
    }
  }

  implicit class AsymmetricCipherKeyPairOps(private val key: AsymmetricCipherKeyPair) extends AnyVal {
    def toKeyPair: java.security.KeyPair = {
      new java.security.KeyPair(key.getPublic.toPublicKey, key.getPrivate.toPrivateKey)
    }
  }

  implicit class AsymmetricKeyParameterOps(private val key: AsymmetricKeyParameter) extends AnyVal {
    def algorithm: String = {
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

    def toPrivateKeyInfo: PrivateKeyInfo = {
      toPrivateKey.toPrivateKeyInfo
    }

    def toPrivateKey: PrivateKey = {
      val keyGenerator = KeyFactory.getInstance(this.algorithm, TLSUtils.provider)
      keyGenerator.generatePrivate(new PKCS8EncodedKeySpec(PrivateKeyInfoFactory.createPrivateKeyInfo(key).getEncoded))
    }

    def toPublicKey: PublicKey = {
      val keyGenerator = KeyFactory.getInstance(this.algorithm, TLSUtils.provider)
      keyGenerator.generatePublic(new X509EncodedKeySpec(SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(key).getEncoded))
    }
  }

  implicit class JavaCertificateOps(private val cert: java.security.cert.Certificate) extends AnyVal {
    def toTlsCertificate: TLS.Certificate = {
      org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded)
    }

    def toTlsCertificateChain: TLS.CertificateChain = {
      toTlsCertificate.toTlsCertificateChain
    }
  }

  implicit class CertificateOps(private val cert: TLS.Certificate) extends AnyVal {
    def toTlsCertificateChain: TLS.CertificateChain = {
      new TLS.CertificateChain(Array(cert))
    }

    def toJavaCertificate: java.security.cert.Certificate = {
      val certificateFactory = CertificateFactory.getInstance("X.509")
      val inputStream = new ByteArrayInputStream(cert.getEncoded)
      try {
        certificateFactory.generateCertificate(inputStream)
      } finally {
        IOUtils.closeQuietly(inputStream)
      }
    }
  }

  implicit class CertificateChainOps(private val chain: TLS.CertificateChain) extends AnyVal {
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
