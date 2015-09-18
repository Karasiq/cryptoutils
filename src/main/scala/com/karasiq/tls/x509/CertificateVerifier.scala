package com.karasiq.tls.x509

import java.io.FileInputStream
import java.net.InetAddress
import java.security.KeyStore
import java.util
import java.util.Date

import com.karasiq.tls.TLS.Certificate
import com.karasiq.tls.{TLS, TLSKeyStore}
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.{GeneralName, KeyUsage}
import org.bouncycastle.cert.X509CertificateHolder

import scala.annotation.tailrec
import scala.util.control.Exception

object CertificateVerifier {
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
  def fromTrustStore(trustStore: KeyStore = CertificateVerifier.defaultTrustStore()): CertificateVerifier = {
    val tlsKeyStore = new TLSKeyStore(trustStore, null)

    val trustedRootCertificates: Set[Certificate] = {
      tlsKeyStore.iterator().collect {
        case e: TLSKeyStore.CertificateEntry ⇒
          e.certificate
      }.toSet
    }

    new CertificateVerifier(trustedRootCertificates)
  }

  /**
   * Creates certificate verifier, which trusts all root certificates without checking
   * @return Certificate verifier
   */
  def trustAll(): CertificateVerifier = new CertificateVerifier(Set.empty) {
    override protected def isCAValid(certificate: Certificate): Boolean = true
  }

  def apply(certs: TLS.Certificate*): CertificateVerifier = {
    new CertificateVerifier(certs.toSet)
  }
}

class CertificateVerifier(val trustedRootCertificates: Set[TLS.Certificate]) {
  protected def isCertificateValid(certificate: TLS.Certificate, issuer: TLS.Certificate): Boolean = {
    val contentVerifierProvider = X509Utils.contentVerifierProvider(issuer)
    val certHolder = new X509CertificateHolder(certificate)

    X509Utils.isCertificationAuthority(issuer) && X509Utils.isKeyUsageAllowed(issuer, KeyUsage.keyCertSign) &&
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
  def isChainValid(chain: List[TLS.Certificate]): Boolean = {
    @tailrec
    def isChainValidRec(chain: List[TLS.Certificate], position: Int): Boolean = {
      chain match {
        case cert :: issuer :: Nil ⇒
          X509Utils.getPathLengthConstraint(issuer).fold(true)(_ >= position) &&
            isCertificateValid(cert, issuer) && isCAValid(issuer)

        case cert :: issuer :: rest ⇒
          X509Utils.getPathLengthConstraint(issuer).fold(true)(_ >= position) &&
            isCertificateValid(cert, issuer) && isChainValidRec(issuer :: rest, position + 1)

        case cert :: Nil ⇒
          isCAValid(cert)

        case _ ⇒
          false
      }
    }

    isChainValidRec(chain, 1)
  }

  /**
   * Ensures that actual hostname matches with X509 CN/SANs
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
        case "www" :: rest ⇒ // Strip WWW
          rest.reverse

        case list ⇒
          list.reverse
      }
    }

    val cnCheck = check(asList(hostName), asList(certHost))
    val sanCheck = {
      val ip = X509Utils.alternativeNameOf(certificate, GeneralName.iPAddress)
      val host = X509Utils.alternativeNameOf(certificate, GeneralName.dNSName)

      ip.fold(false)(ip ⇒ util.Arrays.equals(ip.asInstanceOf[DEROctetString].getOctets, InetAddress.getByName(hostName).getAddress)) ||
        host.fold(false)(dns ⇒ check(asList(dns.toString), asList(InetAddress.getByName(hostName).getHostName)))
    }

    cnCheck || sanCheck
  }
}
