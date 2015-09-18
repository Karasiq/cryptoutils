package com.karasiq.tls.x509

import java.security.PublicKey

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import org.bouncycastle.asn1.x509._
import org.bouncycastle.asn1.{ASN1Encodable, ASN1ObjectIdentifier}
import org.bouncycastle.cert.X509CertificateHolder

case class CertExtension(id: ASN1ObjectIdentifier, value: ASN1Encodable, critical: Boolean = false) {
  require(id ne null)

  override def equals(obj: scala.Any): Boolean = obj match {
    case CertExtension(oid, _, _) ⇒
      this.id == oid

    case _ ⇒
      false
  }

  override def hashCode(): Int = id.hashCode()
}

object CertExtension {
  def wrap(extensionsHolder: Extensions): Set[CertExtension] = {
    val critical = extensionsHolder.getCriticalExtensionOIDs.map { oid ⇒
      CertExtension(oid, extensionsHolder.getExtension(oid).getParsedValue, critical = true)
    }

    val extensions = extensionsHolder.getExtensionOIDs.map { oid ⇒
      CertExtension(oid, extensionsHolder.getExtension(oid).getParsedValue, critical = false)
    }
    critical.toSet ++ extensions.toSet
  }

  def extensionsOf(cert: TLS.Certificate): Set[CertExtension] = {
    wrap(new X509CertificateHolder(cert).getExtensions)
  }

  def basicConstraints(ca: Boolean, pathLenConstraint: Int = 0): CertExtension = {
    if (ca && pathLenConstraint > 0)
      CertExtension(Extension.basicConstraints, new BasicConstraints(pathLenConstraint))
    else
      CertExtension(Extension.basicConstraints, new BasicConstraints(ca))
  }

  def keyUsage(usage: Int): CertExtension = {
    CertExtension(Extension.keyUsage, new KeyUsage(usage))
  }

  def identifiers(key: PublicKey, issuer: Option[TLS.CertificateKey] = None): Set[CertExtension] = {
    val utils = X509Utils.extensionUtils()
    Set(CertExtension(Extension.subjectKeyIdentifier, utils.createSubjectKeyIdentifier(key.toSubjectPublicKeyInfo))) ++ issuer.map { cert ⇒
      CertExtension(Extension.authorityKeyIdentifier, utils.createAuthorityKeyIdentifier(new X509CertificateHolder(cert.certificate)))
    }
  }

  def alternativeName(otherName: String = null, rfc822Name: String = null, dNSName: String = null, x400Address: String = null, directoryName: String = null, ediPartyName: String = null, uniformResourceIdentifier: String = null, iPAddress: String = null, registeredID: String = null, extensionId: ASN1ObjectIdentifier = Extension.subjectAlternativeName): CertExtension = {
    val names = Seq(
      Option(otherName).map(new GeneralName(GeneralName.otherName, _)),
      Option(rfc822Name).map(new GeneralName(GeneralName.rfc822Name, _)),
      Option(dNSName).map(new GeneralName(GeneralName.dNSName, _)),
      Option(x400Address).map(new GeneralName(GeneralName.x400Address, _)),
      Option(directoryName).map(new GeneralName(GeneralName.directoryName, _)),
      Option(ediPartyName).map(new GeneralName(GeneralName.ediPartyName, _)),
      Option(uniformResourceIdentifier).map(new GeneralName(GeneralName.uniformResourceIdentifier, _)),
      Option(iPAddress).map(new GeneralName(GeneralName.iPAddress, _)),
      Option(registeredID).map(new GeneralName(GeneralName.registeredID, _))
    )
    CertExtension(extensionId, new GeneralNames(names.flatten.toArray))
  }

  def defaultExtensions(): Set[CertExtension] = {
    Set(CertExtension.basicConstraints(ca = false), CertExtension.keyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.nonRepudiation))
  }

  def certificationAuthorityExtensions(pathLenConstraint: Int = 0): Set[CertExtension] = {
    Set(CertExtension.basicConstraints(ca = true, pathLenConstraint), CertExtension.keyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.nonRepudiation))
  }
}


















