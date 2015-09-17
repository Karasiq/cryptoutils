import java.io.ByteArrayOutputStream

import com.karasiq.tls.TLSCertificateGenerator.CertExtension
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.{TLSCertificateGenerator, TLSCertificateVerifier, TLSKeyStore}
import org.bouncycastle.asn1.x509.KeyUsage
import org.scalatest.FreeSpec

import scala.util.control.Exception

class X509Test extends FreeSpec {
  "Certificate generator" - {
    val keyGenerator = TLSCertificateGenerator()

    "With generated keys" - {
      def caExtensions() = {
        Set(CertExtension.basicConstraints(ca = true), CertExtension.keyUsage(KeyUsage.keyCertSign | KeyUsage.nonRepudiation))
      }

      def serverExtensions() = {
        TLSCertificateGenerator.defaultExtensions() ++ Set(CertExtension.alternativeName(dNSName = "localhost", iPAddress = "127.0.0.1"))
      }

      val certificationAuthority = keyGenerator.generateEcdsa(TLSCertificateGenerator.subject("Localhost Root CA", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Root CA", "karasiq@karasiq.com"), TLSCertificateGenerator.ellipticCurve("secp256k1"), extensions = caExtensions())

      val serverKeySet = keyGenerator.generateKeySet(TLSCertificateGenerator.subject("Localhost Server", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Server", "karasiq@karasiq.com"), 2048, 1024, TLSCertificateGenerator.ellipticCurve("secp256k1"), Some(certificationAuthority), BigInt(1), extensions = serverExtensions())

      "should sign CSR" in {
        serverKeySet.ecdsa.foreach { key ⇒
          val request = keyGenerator.createRequest(key.key.toKeyPair, key.certificate.getSubject, serverExtensions())
          val cert = keyGenerator.signRequest(request, certificationAuthority)
          val verifier = TLSCertificateVerifier(certificationAuthority.certificate)
          assert(verifier.isChainValid(cert.getCertificateList.toList))
          println("CSR signed: " + cert.toTlsCertificate.getSubject)
        }
      }

      "should create java key store" in {
        val keyStore = new TLSKeyStore(TLSKeyStore.emptyKeyStore())
        keyStore.putCertificate("ca", certificationAuthority.certificate)
        keyStore.putKeySet("test", serverKeySet)
        val outputStream = new ByteArrayOutputStream()
        Exception.allCatch.andFinally(outputStream.close()) {
          keyStore.save(outputStream)
          println(s"Key store size: ${outputStream.size()} bytes")
        }
      }
    }
  }
}
