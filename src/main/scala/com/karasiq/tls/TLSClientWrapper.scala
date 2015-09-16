package com.karasiq.tls

import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.security.SecureRandom

import com.karasiq.tls.internal.{SocketChannelWrapper, TLSUtils}
import org.bouncycastle.crypto.tls._

import scala.concurrent.Await
import scala.concurrent.duration._
import scala.language.postfixOps

class TLSClientWrapper(verifier: TLSCertificateVerifier, address: InetSocketAddress = null) extends TLSConnectionWrapper {
  protected def getClientCertificate(certificateRequest: CertificateRequest): Option[TLS.CertificateKey] = None

  override def apply(connection: SocketChannel): SocketChannel = {
    val protocol = new TlsClientProtocol(SocketChannelWrapper.inputStream(connection), SocketChannelWrapper.outputStream(connection), new SecureRandom())
    val client = new DefaultTlsClient() {
      override def getMinimumVersion: ProtocolVersion = {
        TLSUtils.minVersion()
      }

      override def getCipherSuites: Array[Int] = {
        TLSUtils.defaultCipherSuites()
      }

      override def notifyHandshakeComplete(): Unit = {
        handshake.trySuccess(true)
        onInfo("Selected cipher suite: " + TLSUtils.cipherSuiteAsString(selectedCipherSuite))
      }

      override def getAuthentication: TlsAuthentication = new TlsAuthentication {
        override def getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials = wrapException("Could not provide client credentials") {
          getClientCertificate(certificateRequest)
            .map(ck ⇒ new DefaultTlsSignerCredentials(context, ck.certificateChain, ck.key.getPrivate, TLSUtils.signatureAlgorithm(ck.key.getPrivate))) // Ignores certificateRequest data
            .orNull
        }

        override def notifyServerCertificate(serverCertificate: TLS.CertificateChain): Unit = wrapException("Server certificate error") {
          val chain: List[TLS.Certificate] = serverCertificate.getCertificateList.toList

          if (chain.nonEmpty) {
            onInfo(s"Server certificate chain: ${chain.map(_.getSubject).mkString("; ")}")
            if (address != null && !verifier.isHostValid(chain.head, address.getHostString)) {
              val message = s"Certificate hostname not match: ${address.getHostString}"
              val exc = new TlsFatalAlert(AlertDescription.bad_certificate, new TLSException(message))
              onError(message, exc)
              throw exc
            }
          }

          if (!verifier.isChainValid(chain)) {
            val message = s"Invalid server certificate: ${chain.headOption.fold("<none>")(_.getSubject.toString)}"
            val exc = new TlsFatalAlert(AlertDescription.bad_certificate, new TLSException(message))
            onError(message, exc)
            throw exc
          }
        }
      }
    }

    val socket = wrapException(s"Error connecting to server: $address") {
      protocol.connect(client)
      new SocketChannelWrapper(connection, protocol)
    }
    Await.result(handshake.future, 3 minutes) // Wait for handshake
    socket
  }
}
