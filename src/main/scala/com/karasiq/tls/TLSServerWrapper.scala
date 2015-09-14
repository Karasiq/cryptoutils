package com.karasiq.tls

import java.nio.channels.SocketChannel
import java.security.SecureRandom

import com.karasiq.tls.TLS.CertificateChain
import com.karasiq.tls.internal.{SocketChannelWrapper, TLSUtils}
import org.bouncycastle.crypto.tls._

class TLSServerWrapper(keySet: TLS.KeySet, clientAuth: Boolean = false, verifier: TLSCertificateVerifier = null) extends TLSConnectionWrapper {
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
        onHandshakeFinished()
      }

      private def credentials(cert: TLS.CertificateKey): TlsSignerCredentials = {
        new DefaultTlsSignerCredentials(context, cert.certificateChain, cert.key.getPrivate, TLSUtils.signatureAlgorithm(cert.key.getPrivate))
      }

      override def getRSASignerCredentials: TlsSignerCredentials = wrapException("Could not provide server RSA credentials") {
        keySet.rsa.fold(super.getRSASignerCredentials)(credentials)
      }

      override def getECDSASignerCredentials: TlsSignerCredentials = wrapException("Could not provide server ECDSA credentials") {
        keySet.ecdsa.fold(super.getECDSASignerCredentials)(credentials)
      }

      override def getDSASignerCredentials: TlsSignerCredentials = wrapException("Could not provide server DSA credentials") {
        keySet.dsa.fold(super.getDSASignerCredentials)(credentials)
      }

      override def getRSAEncryptionCredentials: TlsEncryptionCredentials = wrapException("Could not provide server RSA encryption credentials") {
        keySet.rsa.fold(super.getRSAEncryptionCredentials) { cert ⇒
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

    wrapException("Error accepting connection") {
      protocol.accept(server)
      new SocketChannelWrapper(connection, protocol)
    }
  }
}
