package com.karasiq.tls.internal

import java.io._
import java.net.{URI, URL}
import java.nio.ByteBuffer
import java.nio.file.Path

import org.apache.commons.io.IOUtils

import scala.util.control.Exception

trait ObjectLoader[T] {
  def fromInputStream(inputStream: InputStream): T

  def fromResource(resource: String): T = {
    val stream = getClass.getClassLoader.getResourceAsStream(resource)
    Exception.allCatch.andFinally(IOUtils.closeQuietly(stream)) {
      fromInputStream(stream)
    }
  }

  def fromFile(file: File): T = {
    val inputStream = new FileInputStream(file)
    Exception.allCatch.andFinally(IOUtils.closeQuietly(inputStream)) {
      fromInputStream(inputStream)
    }
  }

  final def fromFile(file: Path): T = fromFile(file.toFile)

  final def fromFile(file: String): T = fromFile(new File(file))

  def fromURL(url: URL): T = {
    val inputStream = url.openStream()
    Exception.allCatch.andFinally(IOUtils.closeQuietly(inputStream)) {
      fromInputStream(inputStream)
    }
  }

  final def fromURL(url: String): T = fromURL(new URL(url))

  final def fromURI(uri: URI): T = fromURL(uri.toURL)

  def fromBytes(bytes: Array[Byte]): T = {
    val inputStream = new ByteArrayInputStream(bytes)
    Exception.allCatch.andFinally(IOUtils.closeQuietly(inputStream)) {
      fromInputStream(inputStream)
    }
  }

  final def fromByteBuffer(byteBuffer: ByteBuffer): T = {
    fromBytes(byteBuffer.array())
  }

  final def fromString(str: String, encoding: String): T = {
    fromBytes(str.getBytes(encoding))
  }

  final def fromString(str: String): T = {
    fromBytes(str.getBytes)
  }
}
