package com.karasiq.tls.pem

import java.io._

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.ObjectLoader
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import org.bouncycastle.pkcs.PKCS10CertificationRequest

case class PEMObjectLoader[+T](transform: PartialFunction[AnyRef, T], offset: Int = 0) extends ObjectLoader[T] {
  require(offset >= 0, "Invalid PEM object offset")

  override def fromInputStream(inputStream: InputStream): T = {
    val reader = new PEMParser(new InputStreamReader(inputStream))
    try {
      for (_ ← 0 until offset) reader.readObject()
      transform(reader.readObject())
    } finally {
      IOUtils.closeQuietly(reader)
    }
  }

  def offset(i: Int): PEMObjectLoader[T] = {
    copy(offset = i)
  }
}

/**
 * PEM encoding utility
 */
object PEM {
  @throws[IOException]
  def encode(data: AnyRef): String = {
    val stringWriter = new StringWriter(4096)
    val writer = new JcaPEMWriter(stringWriter)
    try {
      data match {
        case cert: TLS.Certificate ⇒
          writer.writeObject(new X509CertificateHolder(cert))

        case keyPair: AsymmetricCipherKeyPair ⇒
          writer.writeObject(new PEMKeyPair(keyPair.getPublic.toSubjectPublicKeyInfo, keyPair.getPrivate.toPrivateKeyInfo))

        case key: AsymmetricKeyParameter if key.isPrivate ⇒
          writer.writeObject(key.toPrivateKeyInfo)

        case key: AsymmetricKeyParameter if !key.isPrivate ⇒
          writer.writeObject(key.toSubjectPublicKeyInfo)

        case _ ⇒
          writer.writeObject(data)
      }

      writer.flush()
      stringWriter.toString
    } finally {
      IOUtils.closeQuietly(writer)
    }
  }

  @throws[IOException]
  def decode(data: String, offset: Int = 0): AnyRef = {
    val reader = new PEMParser(new StringReader(data))
    try {
      for (_ ← 0 until offset) reader.readObject()
      reader.readObject()
    } finally {
      IOUtils.closeQuietly(reader)
    }
  }

  @throws[IllegalArgumentException]("if object type not match")
  def decodeAs[T](data: String)(implicit m: Manifest[T]) = decode(data) match {
    case result: T ⇒
      result

    case _ ⇒
      throw new IllegalArgumentException("Invalid object type")
  }

  val certificate = PEMObjectLoader {
    case crt: X509CertificateHolder ⇒
      crt.toASN1Structure
  }

  val certificationRequest = PEMObjectLoader {
    case csr: PKCS10CertificationRequest ⇒
      csr
  }

  val publicKey = PEMObjectLoader {
    case sp: SubjectPublicKeyInfo ⇒
      sp

    case kp: PEMKeyPair ⇒
      kp.getPublicKeyInfo
  }

  val privateKey = PEMObjectLoader {
    case pk: PrivateKeyInfo ⇒
      pk

    case kp: PEMKeyPair ⇒
      kp.getPrivateKeyInfo
  }

  val keyPair = PEMObjectLoader {
    case kp: PEMKeyPair ⇒
      new TLS.CertificateKeyPair(kp.getPublicKeyInfo.toAsymmetricKeyParameter, kp.getPrivateKeyInfo.toAsymmetricKeyParameter)
  }
}
