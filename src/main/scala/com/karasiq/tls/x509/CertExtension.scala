package com.karasiq.tls.x509

import com.karasiq.tls.TLS
import org.bouncycastle.asn1.x509._
import org.bouncycastle.asn1.{ASN1Encodable, ASN1ObjectIdentifier, DERSequence}
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
  def wrap(extensionsHolder: Extensions): Seq[CertExtension] = {
    val critical = extensionsHolder.getCriticalExtensionOIDs.map { oid ⇒
      CertExtension(oid, extensionsHolder.getExtension(oid).getParsedValue, critical = true)
    }

    val extensions = extensionsHolder.getNonCriticalExtensionOIDs.map { oid ⇒
      CertExtension(oid, extensionsHolder.getExtension(oid).getParsedValue, critical = false)
    }
    critical.toSeq ++ extensions.toSeq
  }

  def extensionsOf(cert: TLS.Certificate): Seq[CertExtension] = {
    wrap(new X509CertificateHolder(cert).getExtensions)
  }

  def basicConstraints(ca: Boolean, pathLenConstraint: Int = 0): CertExtension = {
    if (ca && pathLenConstraint > 0)
      CertExtension(Extension.basicConstraints, new BasicConstraints(pathLenConstraint), critical = true)
    else
      CertExtension(Extension.basicConstraints, new BasicConstraints(ca), critical = true)
  }

  def keyUsage(usage: Int): CertExtension = {
    CertExtension(Extension.keyUsage, new KeyUsage(usage))
  }

  def authorityKeyId(issuer: TLS.Certificate): CertExtension = {
    val utils = X509Utils.extensionUtils()
    CertExtension(Extension.authorityKeyIdentifier, utils.createAuthorityKeyIdentifier(new X509CertificateHolder(issuer)))
  }

  def subjectKeyId(key: SubjectPublicKeyInfo): CertExtension = {
    val utils = X509Utils.extensionUtils()
    CertExtension(Extension.subjectKeyIdentifier, utils.createSubjectKeyIdentifier(key))
  }

  def identifiers(key: SubjectPublicKeyInfo, issuer: Option[TLS.Certificate] = None): Set[CertExtension] = {
    Set(subjectKeyId(key)) ++ issuer.map(authorityKeyId)
  }

  def alternativeNames(otherName: Seq[String] = Nil, rfc822Name: Seq[String] = Nil, dNSName: Seq[String] = Nil, x400Address: Seq[String] = Nil, directoryName: Seq[String] = Nil, ediPartyName: Seq[String] = Nil, uniformResourceIdentifier: Seq[String] = Nil, iPAddress: Seq[String] = Nil, registeredID: Seq[String] = Nil, extensionId: ASN1ObjectIdentifier = Extension.subjectAlternativeName): CertExtension = {
    val names = Seq(
      otherName.map(new GeneralName(GeneralName.otherName, _)),
      rfc822Name.map(new GeneralName(GeneralName.rfc822Name, _)),
      dNSName.map(new GeneralName(GeneralName.dNSName, _)),
      x400Address.map(new GeneralName(GeneralName.x400Address, _)),
      directoryName.map(new GeneralName(GeneralName.directoryName, _)),
      ediPartyName.map(new GeneralName(GeneralName.ediPartyName, _)),
      uniformResourceIdentifier.map(new GeneralName(GeneralName.uniformResourceIdentifier, _)),
      iPAddress.map(new GeneralName(GeneralName.iPAddress, _)),
      registeredID.map(new GeneralName(GeneralName.registeredID, _))
    )
    CertExtension(extensionId, new GeneralNames(names.flatten.toArray))
  }

  def extendedKeyUsage(keyUsages: KeyPurposeId*): CertExtension = {
    CertExtension(Extension.extendedKeyUsage, new ExtendedKeyUsage(keyUsages.toArray))
  }

  def crlDistributionUrls(issuer: TLS.Certificate, urls: String*): CertExtension = {
    val names = new GeneralNames(urls.map(url ⇒ new GeneralName(GeneralName.uniformResourceIdentifier, url)).toArray)
    val point = new DistributionPoint(new DistributionPointName(names), new ReasonFlags(ReasonFlags.keyCompromise | ReasonFlags.cACompromise | ReasonFlags.certificateHold), new GeneralNames(new GeneralName(issuer.getSubject)))
    CertExtension(Extension.cRLDistributionPoints, new CRLDistPoint(Array(point)))
  }

  def authorityInfoAccess(certUrl: String, ocspUrl: String): CertExtension = {
    val url = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, certUrl))
    val ocsp = new AccessDescription(AccessDescription.id_ad_ocsp, new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl))
    val sequence = new DERSequence(Array[ASN1Encodable](url, ocsp))
    val access = AuthorityInformationAccess.getInstance(sequence)
    CertExtension(Extension.authorityInfoAccess, access)
  }

  def defaultExtensions(): Set[CertExtension] = {
    Set(basicConstraints(ca = false), keyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature | KeyUsage.nonRepudiation), extendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage))
  }

  def certificationAuthorityExtensions(pathLenConstraint: Int = 0): Set[CertExtension] = {
    Set(basicConstraints(ca = true, pathLenConstraint), keyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.nonRepudiation))
  }
}


















