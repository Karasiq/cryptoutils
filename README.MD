# cryptoutils [![Build Status](https://travis-ci.org/Karasiq/cryptoutils.svg?branch=master)](https://travis-ci.org/Karasiq/cryptoutils) [![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.karasiq/cryptoutils_2.12/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.karasiq/cryptoutils_2.12)
Scala wrappers for JCA/BouncyCastle classes

# How to use
Add to `build.sbt`:
```scala
libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.58",
  "com.github.karasiq" %% "cryptoutils" % "1.4.3"
)
```

# Managing key pairs and certificates
## Generating X.509 certificate
```scala
val keyGenerator = CertificateGenerator()

// Self-signed CA certificate
val caSubject = X509Utils.subject("Example Root CA", "US", "California", "San Francisco", "Example", "Example Root CA", "ca@example.com")
val ca: TLS.CertificateKey = keyGenerator.generate(caSubject, "RSA", 2048, extensions = CertExtension.certificationAuthorityExtensions()) 
println(s"Self-signed: ${ca.certificate.getSubject}")

// CA-signed certificate
val subject = X509Utils.subject("Example Subject", "US", "California", "San Francisco", "Example", "Example", "example@example.com")
val cert: TLS.CertificateKey = keyGenerator.generate(subject, "RSA", 2048, Some(ca), BigInt(1))
println(s"CA signed: ${cert.certificate.getSubject}")
```

## X.509 certification request
```scala
val keyGenerator = CertificateGenerator()

val subject = X509Utils.subject("Example Subject", "US", "California", "San Francisco", "Example", "Example", "example@example.com")
val keyPair: java.security.KeyPair = ??? // Generate/load key pair

// Creating request
val request = keyGenerator.createRequest(keyPair, subject)

// Signing request
val ca: TLS.CertificateKey = ... // Certification authority certificate and private key
val cert: TLS.CertificateChain = keyGenerator.signRequest(request, ca) // Resulting certificate chain
```

## Verifying X.509 certificate
```scala
val verifier = CertificateVerifier(CertificateStatusProvider.CRL, ca.certificate) // Or from java trust store: CertificateVerifier.fromTrustStore(TrustStore.fromFile("example-trust.jks"), CertificateStatusProvider.CRL)
if (verifier.isChainValid(cert.certificateChain)) {
  println(s"Verified: ${cert.getSubject}")
}
```

## Using PEM files
```scala
val certificationAuthority = PEM.certificate.fromFile("ca.crt")
val myCertificate = PEM.certificate.fromFile("mycert.crt")
val keyPair = PEM.keyPair.fromFile("mykey.key")

val certKey = TLS.CertificateKey(new TLS.CertificateChain(Array(myCertificate, certificationAuthority)), keyPair)
```

## Using Java Key Store
```scala
// Open key store
val keyStore = TLSKeyStore.open("example.jks", "123456")

// Reading key
val (key, chain) = (keyStore.getKey("example"), keyStore.getCertificateChain("example"))

// Reading key set
val keySet: TLS.KeySet = keyStore.getKeySet("example")

// Adding new key
val newKey: TLS.CertificateKey = ??? // Generate key and certificate (see above)
keyStore.putKey("example-new", newKey)

// Saving to file
keyStore.saveAs("example.jks")
```

# Using TLS (transport layer security)
## TLS client
```scala
val verifier: CertificateVerifier = ??? // Certificate verifier
val clientKeySet: TLS.KeySet = ??? // Client authorization
val address = new InetSocketAddress("example.com", 443) // Server address

// Opening connection:
val clientWrapper = new TLSClientWrapper(verifier, address, clientKeySet)
val socket = clientWrapper(SocketChannel.open(address))
// ... Do read/write, etc ...
socket.close()
```

## TLS server
```scala              
val verifier: CertificateVerifier = ... // Client certificate verifier
val serverKeySet: TLS.KeySet = keyStore.getKeySet("example-server") // Server certificate is required

// Accepting connection
val serverWrapper = new TLSServerWrapper(serverKeySet, clientAuth = true, verifier)
val serverSocket = ServerSocketChannel.open()
serverSocket.bind(new InetSocketAddress("0.0.0.0", 443))

val socket = serverWrapper(serverSocket.accept())
// ... Do read/write, etc ...
socket.close()
```