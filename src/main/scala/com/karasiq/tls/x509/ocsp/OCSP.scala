package com.karasiq.tls.x509.ocsp

import java.net.URL
import java.security.SecureRandom
import java.time.Instant
import java.util.Date

import com.karasiq.tls.TLS
import com.karasiq.tls.internal.BCConversions._
import com.karasiq.tls.internal.TLSUtils
import com.karasiq.tls.x509.X509Utils
import org.apache.commons.io.IOUtils
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.{CRLReason, ExtensionsGenerator, KeyUsage}
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp._
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.encoders.Base64

import scala.util.control.Exception

/**
 * Online Certificate Status Protocol (OCSP) utility
 * @see [[https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol]]
 */
object OCSP {
  /**
   * OCSP certificate status
   * @param id Certificate ID
   * @param status Certificate status
   */
  case class Status(id: CertificateID, status: CertificateStatus = Status.good()) {
    def isRevoked: Boolean = status.ne(null) && status.isInstanceOf[RevokedStatus]
  }

  object Status {
    /**
     * OCSP good status
     * @return Good status
     */
    def good(): CertificateStatus = CertificateStatus.GOOD

    /**
     * OCSP revoked status
     * @param reason Revocation reason
     * @param date Revocation date
     * @return Revoked status
     */
    def revoked(reason: Int = CRLReason.unspecified, date: Instant = Instant.now()): CertificateStatus = {
      new RevokedStatus(Date.from(date), reason)
    }

    def wrap(responses: Array[SingleResp]): Seq[Status] = responses.map { resp ⇒
      Status(resp.getCertID, resp.getCertStatus)
    }
  }

  private val digestCalculator: DigestCalculator = new JcaDigestCalculatorProviderBuilder()
    .setProvider(TLSUtils.provider)
    .build()
    .get(CertificateID.HASH_SHA1)

  private val secureRandom = new SecureRandom()

  /**
   * OCSP certificate ID
   * @param issuer Issuer certificate
   * @param serial Certificate serial number
   * @return OCSP certificate ID
   */
  def id(issuer: TLS.Certificate, serial: BigInt): CertificateID = {
    new CertificateID(digestCalculator, new X509CertificateHolder(issuer), serial.underlying())
  }

  /**
   * Creates signed OCSP request
   * @param signer Signer credentials
   * @param ids Certificate IDs
   * @return Signed OCSP request
   */
  def signedRequest(signer: TLS.CertificateKey, ids: CertificateID*): OCSPReq = {
    val builder = ids.foldLeft(new OCSPReqBuilder())((builder, id) ⇒ builder.addRequest(id))
    builder.setRequestorName(signer.certificate.getSubject)

    val extGen = new ExtensionsGenerator()
    val nonce: DEROctetString = {
      val bytes = new Array[Byte](16)
      secureRandom.nextBytes(bytes)
      new DEROctetString(bytes)
    }

    extGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, nonce)
    builder.setRequestExtensions(extGen.generate())

    builder.build(X509Utils.contentSigner(signer.key.getPrivate.toPrivateKey), signer.certificateChain.getCertificateList.map(new X509CertificateHolder(_)))
  }

  /**
   * Creates unsigned OCSP request
   * @param ids Certificate IDs
   * @return OCSP request
   */
  def request(ids: CertificateID*): OCSPReq = {
    val builder = ids.foldLeft(new OCSPReqBuilder())((builder, id) ⇒ builder.addRequest(id))
    builder.build()
  }

  /**
   * Basic OCSP response
   * @param signer Signer credentials
   * @param statuses Certificate statuses list
   * @return OCSP response
   */
  def response(signer: TLS.CertificateKey, statuses: Status*): BasicOCSPResp = {
    val builder = statuses.foldLeft[BasicOCSPRespBuilder](new JcaBasicOCSPRespBuilder(signer.key.getPublic.toPublicKey, digestCalculator)) {
      case (b, Status(id, status)) ⇒
        b.addResponse(id, status)
    }
    builder.build(X509Utils.contentSigner(signer.key.getPrivate.toPrivateKey), signer.certificateChain.getCertificateList.map(new X509CertificateHolder(_)), new Date())
  }

  private def loadUrl(url: String, request: OCSPReq): OCSPResp = {
    val encoded = Base64.toBase64String(request.getEncoded)
    val ocspUrl = new URL(if (url.endsWith("/")) url + encoded else url + "/" + encoded)
    val inputStream = ocspUrl.openStream()
    Exception.allCatch.andFinally(IOUtils.closeQuietly(inputStream)) {
      new OCSPResp(inputStream)
    }
  }

  /**
   * Ensures that OCSP response signature is valid
   * @param r OCSP response
   * @param issuer OCSP issuer
   * @return Is signature valid
   */
  def verify(r: BasicOCSPResp, issuer: TLS.Certificate): Boolean = {
    X509Utils.isKeyUsageAllowed(issuer, KeyUsage.cRLSign) &&
      r.isSignatureValid(X509Utils.contentVerifierProvider(issuer))
  }

  /**
   * Ensures that OCSP request signature is valid
   * @param r OCSP request
   * @param issuer OCSP issuer
   * @return Is signature valid
   */
  def verify(r: OCSPReq, issuer: TLS.Certificate): Boolean = {
    X509Utils.isKeyUsageAllowed(issuer, KeyUsage.digitalSignature) &&
      r.isSignatureValid(X509Utils.contentVerifierProvider(issuer))
  }

  /**
   * Tries to load OCSP response from URL
   * @param ocsp OCSP URL
   * @param issuer OCSP issuer
   * @param request OCSP request
   * @return OCSP response or [[None]]
   */
  def fromUrl(ocsp: String, issuer: TLS.Certificate, request: OCSPReq): Option[BasicOCSPResp] = {
    val response = loadUrl(ocsp, request)
    assert(response.getStatus == OCSPResp.SUCCESSFUL, s"OCSP error: ${response.getStatus}")
    response.getResponseObject match {
      case r: BasicOCSPResp if verify(r, issuer) ⇒
        Some(r)

      case _ ⇒
        None
    }
  }

  /**
   * Checks certificate online status
   * @param cert Certificate
   * @param issuer Issuer
   * @return Certificate OCSP status
   */
  def getStatus(cert: TLS.Certificate, issuer: TLS.Certificate): Option[Status] = X509Utils.getOcspUrl(cert).flatMap { ocsp ⇒
    val certId = id(issuer, BigInt(cert.getSerialNumber.getValue))
    fromUrl(ocsp, issuer, request(certId))
      .toSeq
      .flatMap(_.getResponses)
      .find(_.getCertID == certId)
      .map(r ⇒ Status(r.getCertID, r.getCertStatus))
  }
}
