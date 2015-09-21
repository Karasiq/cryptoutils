package com.karasiq.tls.x509

import java.io.FileInputStream
import java.net.InetAddress
import java.security.KeyStore
import java.util
import java.util.Date

import com.karasiq.tls.TLS.Certificate
import com.karasiq.tls.{TLS, TLSKeyStore}
import com.typesafe.config.ConfigFactory
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.{GeneralName, KeyUsage}
import org.bouncycastle.asn1.{ASN1Encodable, DEROctetString}
import org.bouncycastle.cert.X509CertificateHolder

import scala.annotation.tailrec
import scala.util.Try
import scala.util.control.Exception

trait CertificateVerifier {
  /**
   * Checks that provided certificate signature is valid
   * @param certificate Certificate
   * @param issuer Issuer certificate
   * @return Is signature valid
   */
  def isCertificateValid(certificate: TLS.Certificate, issuer: TLS.Certificate): Boolean

  /**
   * Checks that CA certificate is trusted
   * @param certificate Certification authority certificate
   * @return Is CA certificate trusted and valid
   */
  def isCAValid(certificate: TLS.Certificate): Boolean

  /**
   * Checks certificate chain for validity
   * @param chain X509 certificate chain
   * @return Is provided certificate chain valid
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
  def isHostValid(certificate: TLS.Certificate, hostName: String): Boolean

  /**
   * Trusted root certificates
   * @return Set of trusted root CA certificates
   */
  def trustedRootCertificates: Set[TLS.Certificate]
}

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

    new CertificateVerifierImpl(trustedRootCertificates)
  }

  /**
   * Creates certificate verifier, which trusts all root certificates without checking
   * @return Certificate verifier
   */
  def trustAll(): CertificateVerifier = new CertificateVerifierImpl(Set.empty) {
    override def isCAValid(certificate: Certificate): Boolean = true
  }

  /**
   * Creates certificate verifier from set of trusted certificates
   * @param certs Trusted root CAs
   * @return Certificate verifier
   */
  def apply(certs: TLS.Certificate*): CertificateVerifier = {
    new CertificateVerifierImpl(certs.toSet)
  }
}

class CertificateVerifierImpl(override val trustedRootCertificates: Set[TLS.Certificate]) extends CertificateVerifier {
  override def isCertificateValid(certificate: TLS.Certificate, issuer: TLS.Certificate): Boolean = {
    val contentVerifierProvider = X509Utils.contentVerifierProvider(issuer)
    val certHolder = new X509CertificateHolder(certificate)

    X509Utils.isCertificationAuthority(issuer) && X509Utils.isKeyUsageAllowed(issuer, KeyUsage.keyCertSign) &&
      X509Utils.verifyAuthorityIdentifier(certificate, issuer).getOrElse(true) &&
      X509Utils.verifyPublicKeyIdentifier(certificate, certificate.getSubjectPublicKeyInfo).getOrElse(true) &&
      certHolder.isValidOn(new Date()) && certHolder.isSignatureValid(contentVerifierProvider)
  }

  override def isCAValid(certificate: TLS.Certificate): Boolean = {
    // CA authority
    trustedRootCertificates.find(_.getSubject == certificate.getIssuer).exists { ca ⇒
      isCertificateValid(certificate, ca) // Verify with stored root CA certificate
    }
  }

  override def isHostValid(certificate: TLS.Certificate, hostName: String): Boolean = {
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

    def checkIp(hostName: String, ip: ASN1Encodable): Boolean = {
      Try(util.Arrays.equals(ip.asInstanceOf[DEROctetString].getOctets, InetAddress.getByName(hostName).getAddress))
        .getOrElse(false)
    }

    val cnCheck = check(asList(hostName), asList(certHost))
    val sanCheck = {
      val ip = X509Utils.alternativeNameOf(certificate, GeneralName.iPAddress)
      val host = X509Utils.alternativeNameOf(certificate, GeneralName.dNSName)

      ip.exists(ip ⇒ checkIp(hostName, ip)) ||
        host.exists(dns ⇒ check(asList(dns.toString), asList(InetAddress.getByName(hostName).getHostName)))
    }

    cnCheck || sanCheck
  }
}
