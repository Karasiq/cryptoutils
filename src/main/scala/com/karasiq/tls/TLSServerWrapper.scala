package com.karasiq.tls

import java.nio.channels.SocketChannel
import java.security.SecureRandom

import com.karasiq.tls.TLS.CertificateChain
import com.karasiq.tls.internal.BCConversions.CipherSuiteId
import com.karasiq.tls.internal.{SocketChannelWrapper, TLSUtils}
import com.karasiq.tls.x509.{CertificateVerifier, X509Utils}
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.crypto.tls._

import scala.concurrent.Await
import scala.concurrent.duration._
import scala.language.postfixOps

class TLSServerWrapper(keySet: TLS.KeySet, clientAuth: Boolean = false, verifier: CertificateVerifier = null) extends TLSConnectionWrapper {
  require(verifier != null || !clientAuth, "No client certificate verifier provided")

  @throws(classOf[TlsFatalAlert])
  protected def onClientAuth(clientCertificate: CertificateChain): Unit = {
    val chain: List[TLS.Certificate] = clientCertificate.getCertificateList.toList
    if (chain.nonEmpty) {
      onInfo(s"Client certificate chain: ${chain.map(_.getSubject).mkString("; ")}")
    }

    if (clientAuth && !verifier.isChainValid(chain)) {
      val message = s"Invalid client certificate: ${chain.headOption.fold("<none>")(_.getSubject.toString)}"
      val exc = new TlsFatalAlert(AlertDescription.bad_certificate, new TLSException(message))
      onError(message, exc)
      throw exc
    }
  }

  def apply(connection: SocketChannel): SocketChannel = {
    val protocol = new TlsServerProtocol(SocketChannelWrapper.inputStream(connection), SocketChannelWrapper.outputStream(connection), new SecureRandom())
    val server = new DefaultTlsServer() {
      override def getMinimumVersion: ProtocolVersion = {
        TLSUtils.minVersion()
      }

      override def getMaximumVersion: ProtocolVersion = {
        TLSUtils.maxVersion()
      }

      override def getCipherSuites: Array[Int] = {
        TLSUtils.defaultCipherSuites()
      }

      override def notifyHandshakeComplete(): Unit = {
        handshake.trySuccess(true)
        onInfo(s"Selected cipher suite: ${CipherSuiteId.asString(selectedCipherSuite)}")
      }

      private def signerCredentials(certOption: Option[TLS.CertificateKey]): TlsSignerCredentials = {
        certOption.filter(c ⇒ X509Utils.isKeyUsageAllowed(c.certificate, KeyUsage.digitalSignature)).fold(throw new TLSException("No suitable signer credentials found")) { cert ⇒
          new DefaultTlsSignerCredentials(context, cert.certificateChain, cert.key.getPrivate, TLSUtils.signatureAlgorithm(cert.key.getPrivate))
        }
      }

      override def getRSASignerCredentials: TlsSignerCredentials = wrapException("Could not provide server RSA credentials") {
        signerCredentials(keySet.rsa)
      }

      override def getECDSASignerCredentials: TlsSignerCredentials = wrapException("Could not provide server ECDSA credentials") {
        signerCredentials(keySet.ecdsa)
      }

      override def getDSASignerCredentials: TlsSignerCredentials = wrapException("Could not provide server DSA credentials") {
        signerCredentials(keySet.dsa)
      }

      override def getRSAEncryptionCredentials: TlsEncryptionCredentials = wrapException("Could not provide server RSA encryption credentials") {
        keySet.rsa.filter(c ⇒ X509Utils.isKeyUsageAllowed(c.certificate, KeyUsage.keyEncipherment)).fold(super.getRSAEncryptionCredentials) { cert ⇒
          new DefaultTlsEncryptionCredentials(context, cert.certificateChain, cert.key.getPrivate)
        }
      }

      override def getCertificateRequest: CertificateRequest = {
        if (clientAuth) {
          TLSUtils.certificateRequest(this.getServerVersion, verifier)
        } else {
          null
        }
      }

      override def notifyClientCertificate(clientCertificate: CertificateChain): Unit = wrapException("Client certificate error") {
        onClientAuth(clientCertificate)
      }
    }

    val socket = wrapException("Error accepting connection") {
      protocol.accept(server)
      new SocketChannelWrapper(connection, protocol)
    }
    Await.result(handshake.future, 3 minutes) // Wait for handshake
    socket
  }
}
