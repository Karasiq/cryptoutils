package com.karasiq.tls.pem

import java.io.{FileInputStream, StringReader, StringWriter}

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.AsymmetricKeyParameter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import org.bouncycastle.pkcs.PKCS10CertificationRequest

import scala.util.Try
import scala.util.control.Exception

object PEM {
  def encode(data: AnyRef): String = {
    val stringWriter = new StringWriter(4096)
    val writer = new JcaPEMWriter(stringWriter)
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
  }

  def decode(data: String): AnyRef = {
    val reader = new PEMParser(new StringReader(data))
    reader.readObject()
  }

  def decodeAs[T](data: String)(implicit m: Manifest[T]) = decode(data) match {
    case result: T ⇒
      result

    case _ ⇒
      throw new IllegalArgumentException("Invalid object type")
  }

  def file(path: String): String = {
    val inputStream = new FileInputStream(path)
    Exception.allCatch.andFinally(IOUtils.closeQuietly(inputStream)) {
      IOUtils.toString(inputStream, "ASCII")
    }
  }

  def certificate(data: String): TLS.Certificate = {
    decodeAs[X509CertificateHolder](data).toASN1Structure
  }

  def certificationRequest(data: String): PKCS10CertificationRequest = decodeAs[PKCS10CertificationRequest](data)

  def publicKey(data: String): SubjectPublicKeyInfo = {
    Try(decodeAs[SubjectPublicKeyInfo](data))
      .getOrElse(decodeAs[PEMKeyPair](data).getPublicKeyInfo)
  }

  def privateKey(data: String): PrivateKeyInfo = {
    Try(decodeAs[PrivateKeyInfo](data))
      .getOrElse(decodeAs[PEMKeyPair](data).getPrivateKeyInfo)
  }

  def keyPair(data: String): AsymmetricCipherKeyPair = {
    val kp = decodeAs[PEMKeyPair](data)
    new AsymmetricCipherKeyPair(kp.getPublicKeyInfo.toAsymmetricKeyParameter, kp.getPrivateKeyInfo.toAsymmetricKeyParameter)
  }
}
