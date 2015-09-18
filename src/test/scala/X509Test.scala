import java.io.ByteArrayOutputStream

import com.karasiq.tls.TLSKeyStore
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.TLSUtils
import com.karasiq.tls.x509.{CertExtension, CertificateGenerator, CertificateVerifier, X509Utils}
import org.scalatest.{FreeSpec, Matchers}

import scala.util.control.Exception

class X509Test extends FreeSpec with Matchers {
  "Certificate generator" - {
    val keyGenerator = CertificateGenerator()

    "With generated keys" - {
      val certificationAuthority = keyGenerator.generateEcdsa(X509Utils.subject("Localhost Root CA", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Root CA", "karasiq@karasiq.com"), TLSUtils.getEllipticCurve("secp256k1"), extensions = CertExtension.certificationAuthorityExtensions(1))

      val serverKeySet = keyGenerator.generateKeySet(X509Utils.subject("Localhost Server", "US", "California", "San Francisco", "Karasiq", "Cryptoutils Test Server", "karasiq@karasiq.com"), 2048, 1024, TLSUtils.getEllipticCurve("secp256k1"), Some(certificationAuthority), BigInt(1))


      "should verify extensions" in {
        X509Utils.compareAuthorityIdentifier(serverKeySet.rsa.get.certificate, certificationAuthority.certificate) shouldBe Some(true)
        X509Utils.comparePublicKeyIdentifier(serverKeySet.dsa.get.certificate, serverKeySet.dsa.get.key.getPublic.toSubjectPublicKeyInfo) shouldBe Some(true)
        X509Utils.getPathLengthConstraint(certificationAuthority.certificate) shouldBe Some(1)
      }

      "should sign CSR" in {
        serverKeySet.ecdsa.foreach { key ⇒
          val request = keyGenerator.createRequest(key.key.toKeyPair, key.certificate.getSubject)
          val cert = keyGenerator.signRequest(request, certificationAuthority)
          val verifier = CertificateVerifier(certificationAuthority.certificate)
          assert(verifier.isChainValid(cert.getCertificateList.toList))
          X509Utils.compareAuthorityIdentifier(cert.toTlsCertificate, certificationAuthority.certificate) shouldBe Some(true)
          X509Utils.comparePublicKeyIdentifier(cert.toTlsCertificate, serverKeySet.ecdsa.get.key.getPublic.toSubjectPublicKeyInfo) shouldBe Some(true)
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
