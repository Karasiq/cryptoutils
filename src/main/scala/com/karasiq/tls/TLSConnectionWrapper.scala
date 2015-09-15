package com.karasiq.tls

import java.nio.channels.SocketChannel

import org.bouncycastle.crypto.tls.{AlertDescription, TlsFatalAlert}

import scala.concurrent.Promise
import scala.util.control.Exception

trait TLSConnectionWrapper {
  protected val handshake: Promise[Boolean] = Promise()

  protected def onError(message: String, exc: Throwable): Unit = { }

  protected def onInfo(message: String): Unit = { }

  protected def wrapException[T](message: String)(f: ⇒ T): T = {
    val catcher = Exception.allCatch.withApply { exc ⇒
      handshake.tryFailure(exc)
      if (exc.isInstanceOf[TlsFatalAlert]) throw exc
      else {
        onError(message, exc)
        throw new TlsFatalAlert(AlertDescription.internal_error, new TLSException(message, exc))
      }
    }
    catcher(f)
  }

  def apply(connection: SocketChannel): SocketChannel
}
