import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.{ServerSocketChannel, SocketChannel}

import com.karasiq.tls._
import com.karasiq.tls.internal.TLSUtils
import com.karasiq.tls.x509._
import org.scalatest.{FlatSpec, Matchers}

import scala.concurrent.duration._
import scala.concurrent.{Await, Promise}
import scala.language.postfixOps
import scala.util.control.Exception

class TLSTest extends FlatSpec with Matchers {
  private def asByteBuffer(s: String): ByteBuffer = {
    ByteBuffer.wrap(s.getBytes("utf-8"))
  }

  private def read(socket: SocketChannel): String = {
    val byteBuffer = ByteBuffer.allocate(2048)
    val readLength = socket.read(byteBuffer)
    if (readLength > 0) {
      val array = new Array[Byte](readLength)
      byteBuffer.flip()
      byteBuffer.get(array)
      new String(array, "utf-8")
    } else {
      ""
    }
  }

  "TLS client" should "connect to HTTPS" in {
    val address = new InetSocketAddress("howsmyssl.com", 443)

    val wrapper = new TLSClientWrapper(CertificateVerifier.trustAll(), address) {
      override protected def onInfo(message: String): Unit = {
        println(message)
      }

      override protected def onError(message: String, exc: Throwable): Unit = {
        println(s"$message")
        exc.printStackTrace()
      }
    }

    val socket = SocketChannel.open(address)
    Exception.allCatch.andFinally(socket.close()) {
      val tlsSocket = wrapper(socket)
      tlsSocket.write(asByteBuffer(s"GET /a/check HTTP/1.1\r\nHost: www.${address.getHostName}\r\n\r\n"))
      val response = read(tlsSocket)
      println(response)
      assert(response.startsWith("HTTP/1.1 200 OK"))
      tlsSocket.close()
    }
  }

  "TLS server" should "accept connection" in {
    val keyGenerator = CertificateGenerator()

    def serverExtensions() = {
      CertExtension.defaultExtensions() ++ Set(CertExtension.alternativeName(dNSName = "localhost", iPAddress = "127.0.0.1"))
    }

    val certificationAuthority = keyGenerator.generateEcdsa(X509Utils.subject("Localhost Root CA", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Root CA", "karasiq@karasiq.com"), TLSUtils.getEllipticCurve("secp256k1"), extensions = CertExtension.certificationAuthorityExtensions(1))

    val serverKeySet = keyGenerator.generateKeySet(X509Utils.subject("Localhost Server", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Server", "karasiq@karasiq.com"), 2048, 1024, TLSUtils.getEllipticCurve("secp256k1"), Some(certificationAuthority), BigInt(1), extensions = serverExtensions())

    val clientKeySet = keyGenerator.generateKeySet(X509Utils.subject("Localhost Client", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Client", "karasiq@karasiq.com"), 2048, 1024, TLSUtils.getEllipticCurve("secp256k1"), Some(certificationAuthority), BigInt(2))

    val verifier = CertificateVerifier(CertificateStatusProvider.alwaysValid, certificationAuthority.certificate)

    val localhost = new InetSocketAddress("127.0.0.1", 4443)

    val promisedClientResult = Promise[String]()
    val promisedServerResult = Promise[String]()

    val clientWrapper = new TLSClientWrapper(verifier, localhost, clientKeySet) {
      override protected def onInfo(message: String): Unit = {
        println(s"Client: $message")
      }

      override protected def onError(message: String, exc: Throwable): Unit = {
        println(s"Client: $message")
        exc.printStackTrace()
      }
    }

    val serverWrapper = new TLSServerWrapper(serverKeySet, true, verifier) {
      override protected def onInfo(message: String): Unit = {
        println(s"Server: $message")
      }

      override protected def onError(message: String, exc: Throwable): Unit = {
        println(s"Server: $message")
        exc.printStackTrace()
      }
    }

    val clientThread = new Thread(new Runnable {
      override def run(): Unit = {
        val socket = SocketChannel.open(localhost)
        val catcher = Exception.allCatch.withApply {exc ⇒ promisedClientResult.tryFailure(exc); throw exc}.andFinally(socket.close())
        catcher {
          val tlsSocket = clientWrapper(socket)
          tlsSocket.write(asByteBuffer("Client hello"))
          promisedClientResult.trySuccess(read(tlsSocket))
          tlsSocket.close()
        }
      }
    })

    val serverThread = new Thread(new Runnable {
      override def run(): Unit = {
        val socket = ServerSocketChannel.open()
        val catcher = Exception.allCatch.withApply {exc ⇒ promisedServerResult.tryFailure(exc); throw exc}.andFinally(socket.close())
        catcher {
          socket.bind(localhost)
          val clientSocket = socket.accept()
          Exception.allCatch.andFinally(clientSocket.close()) {
            val tlsSocket = serverWrapper(clientSocket)
            promisedServerResult.trySuccess(read(tlsSocket))
            tlsSocket.write(asByteBuffer("Server hello"))
            tlsSocket.close()
          }
        }
      }
    })

    serverThread.setName("TLS-test-server")
    serverThread.start()

    clientThread.setName("TLS-test-client")
    clientThread.start()

    val serverResult = Await.result(promisedServerResult.future, 3 minutes)
    val clientResult = Await.result(promisedClientResult.future, 3 minutes)

    serverResult shouldBe "Client hello"
    clientResult shouldBe "Server hello"
  }
}
