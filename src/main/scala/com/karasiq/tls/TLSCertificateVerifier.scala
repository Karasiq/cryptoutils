package com.karasiq.tls

import java.io.FileInputStream
import java.net.InetAddress
import java.security.KeyStore
import java.util
import java.util.Date

import com.karasiq.tls.TLS.Certificate
import com.karasiq.tls.internal.TLSUtils
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.{GeneralName, KeyUsage}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder

import scala.annotation.tailrec
import scala.util.control.Exception

object TLSCertificateVerifier {
  /**
   * Opens specified JKS trust store
   * @param path Trust store file path
   * @return JKS trust store
   */
  def trustStore(path: String): KeyStore = {
    val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)

    val inputStream = new FileInputStream(path)
    Exception.allCatch.andFinally(inputStream.close()) {
      trustStore.load(inputStream, null)
      trustStore
    }
  }

  /**
   * Opens JKS trust store specified in configuration
   * @return JKS trust store
   */
  def defaultTrustStore(): KeyStore = {
    val config = ConfigFactory.load().getConfig("karasiq.tls")
    this.trustStore(config.getString("trust-store"))
  }

  /**
   * Creates certificate verifier from JKS trust store
   * @param trustStore Trust store
   * @return Certificate verifier
   */
  def fromTrustStore(trustStore: KeyStore = TLSCertificateVerifier.defaultTrustStore()): TLSCertificateVerifier = {
    val tlsKeyStore = new TLSKeyStore(trustStore, null)

    val trustedRootCertificates: Set[Certificate] = {
      tlsKeyStore.iterator().collect {
        case e: TLSKeyStore.CertificateEntry ⇒
          e.certificate
      }.toSet
    }

    new TLSCertificateVerifier(trustedRootCertificates)
  }

  /**
   * Creates certificate verifier, which trusts all root certificates without checking
   * @return Certificate verifier
   */
  def trustAll(): TLSCertificateVerifier = new TLSCertificateVerifier(Set.empty) {
    override protected def isCAValid(certificate: Certificate): Boolean = true
  }

  def apply(certs: TLS.Certificate*): TLSCertificateVerifier = {
    new TLSCertificateVerifier(certs.toSet)
  }
}

class TLSCertificateVerifier(val trustedRootCertificates: Set[TLS.Certificate]) {
  private val bcProvider = new BouncyCastleProvider

  protected def isCertificateValid(certificate: TLS.Certificate, issuer: TLS.Certificate): Boolean = {
    val contentVerifierProvider = new JcaContentVerifierProviderBuilder()
      .setProvider(bcProvider)
      .build(new X509CertificateHolder(issuer))

    val certHolder = new X509CertificateHolder(certificate)

    TLSUtils.isCertificateAuthority(issuer) && TLSUtils.isKeyUsageAllowed(issuer, KeyUsage.keyCertSign) &&
      certHolder.isValidOn(new Date()) && certHolder.isSignatureValid(contentVerifierProvider)
  }

  protected def isCAValid(certificate: TLS.Certificate): Boolean = {
    // CA authority
    trustedRootCertificates.find(_.getSubject == certificate.getIssuer).fold(false) { ca ⇒
      isCertificateValid(certificate, ca) // Verify with stored root CA certificate
    }
  }

  /**
   * Checks certificate chain for validity
   * @param chain X509 certificate chain
   * @return Is chain valid
   */
  @tailrec
  final def isChainValid(chain: List[TLS.Certificate]): Boolean = {
    chain match {
      case cert :: issuer :: Nil ⇒
        isCertificateValid(cert, issuer) && isCAValid(issuer)

      case cert :: issuer :: rest ⇒
        isCertificateValid(cert, issuer) && isChainValid(issuer :: rest)

      case cert :: Nil ⇒
        isCAValid(cert)

      case _ ⇒
        false
    }
  }

  /**
   * Ensures that actual hostname matches with X509 CN
   * @param certificate X509 certificate
   * @param hostName Actual hostname
   * @return Is hostname valid
   */
  def isHostValid(certificate: TLS.Certificate, hostName: String): Boolean = {
    val certHost: String = certificate.getSubject.getRDNs(BCStyle.CN).head.getFirst.getValue.toString

    @tailrec
    def check(actual: List[String], cert: List[String]): Boolean = {
      (actual, cert) match {
        case (Nil, Nil) ⇒
          true

        case (_, "*" :: _) ⇒
          true

        case (actualPart :: actualRest, certPart :: certRest) if actualPart.compareToIgnoreCase(certPart) == 0 ⇒
          check(actualRest, certRest)

        case _ ⇒
          false
      }
    }

    def asList(s: String) = {
      s.split('.').toList match {
        case "www" :: rest ⇒
          rest.reverse

        case list ⇒
          list.reverse
      }
    }

    val cnCheck = check(asList(hostName), asList(certHost))
    val sanCheck = {
      val ip = TLSUtils.alternativeName(certificate, GeneralName.iPAddress)
      val host = TLSUtils.alternativeName(certificate, GeneralName.dNSName)

      ip.fold(false)(ip ⇒ util.Arrays.equals(ip.asInstanceOf[DEROctetString].getOctets, InetAddress.getByName(hostName).getAddress)) ||
        host.fold(false)(dns ⇒ check(asList(dns.toString), asList(InetAddress.getByName(hostName).getHostName)))
    }

    cnCheck || sanCheck
  }
}
