name := "cryptoutils"

organization := "com.github.karasiq"

version := "1.4.0"

isSnapshot := version.value.endsWith("SNAPSHOT")

scalaVersion := "2.11.8"

resolvers += "softprops-maven" at "http://dl.bintray.com/content/softprops/maven"

libraryDependencies ++= Seq(
  "commons-io" % "commons-io" % "2.4",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.52",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.52",
  "com.typesafe" % "config" % "1.3.0",
  "org.scalatest" %% "scalatest" % "2.2.4" % "test"
)

scalacOptions ++= Seq("-optimize", "-deprecation", "-feature")

publishMavenStyle := true

publishTo := {
  val nexus = "https://oss.sonatype.org/"
  if (isSnapshot.value)
    Some("snapshots" at nexus + "content/repositories/snapshots")
  else
    Some("releases" at nexus + "service/local/staging/deploy/maven2")
}

publishArtifact in Test := false

pomIncludeRepository := { _ ⇒ false }

licenses := Seq("The MIT License" → url("http://opensource.org/licenses/MIT"))

homepage := Some(url("https://github.com/Karasiq/" + name.value))

pomExtra := <scm>
  <url>git@github.com:Karasiq/{name.value}.git</url>
  <connection>scm:git:git@github.com:Karasiq/{name.value}.git</connection>
</scm>
  <developers>
    <developer>
      <id>karasiq</id>
      <name>Piston Karasiq</name>
      <url>https://github.com/Karasiq</url>
    </developer>
  </developers>