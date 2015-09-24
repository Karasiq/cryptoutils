package com.karasiq.tls.x509

import java.io.InputStream
import java.security.KeyStore

import com.karasiq.tls.internal.ObjectLoader
import com.typesafe.config.ConfigFactory

/**
 * Trust store loader utility
 */
object TrustStore extends ObjectLoader[KeyStore] {
  override def fromInputStream(inputStream: InputStream): KeyStore = {
    val trustStore = KeyStore.getInstance(KeyStore.getDefaultType)
    trustStore.load(inputStream, null)
    trustStore
  }

  /**
   * Opens JKS trust store specified in configuration
   * @return JKS trust store
   */
  def default(): KeyStore = {
    val config = ConfigFactory.load().getConfig("karasiq.tls")
    fromFile(config.getString("trust-store"))
  }
}
