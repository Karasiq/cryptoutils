name := "cryptoutils"

organization := "com.karasiq"

version := "1.0"

scalaVersion := "2.11.7"

resolvers += "softprops-maven" at "http://dl.bintray.com/content/softprops/maven"

libraryDependencies ++= Seq(
  "commons-io" % "commons-io" % "2.4",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.52",
  "com.typesafe" % "config" % "1.3.0",
  "org.scalatest" %% "scalatest" % "2.2.4" % "test"
)

scalacOptions ++= Seq("-optimize", "-deprecation", "-feature")