package com.karasiq.tls.x509

import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x509.{Extensions, ExtensionsGenerator}
import org.bouncycastle.pkcs.PKCS10CertificationRequest

import scala.util.Try

object CSRUtils {
  def extensionsOf(csr: PKCS10CertificationRequest): Set[CertExtension] = {
    Try(CertExtension.wrap(Extensions.getInstance(csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest).head.getAttrValues.getObjectAt(0)))).getOrElse(Set())
  }

  def encodeExtensions(extensions: Set[CertExtension]): ASN1Encodable = {
    val extGen = new ExtensionsGenerator()
    extensions.foreach { e ⇒
      extGen.addExtension(e.id, e.critical, e.value)
    }
    extGen.generate()
  }
}
