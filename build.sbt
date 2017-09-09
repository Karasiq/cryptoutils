name := "cryptoutils"

organization := "com.github.karasiq"

version := "1.4.3"

isSnapshot := version.value.endsWith("SNAPSHOT")

scalaVersion := "2.12.3"

crossScalaVersions := Seq("2.11.11", "2.12.3")

resolvers += "softprops-maven" at "http://dl.bintray.com/content/softprops/maven"

libraryDependencies ++= Seq(
  "commons-io" % "commons-io" % "2.5",
  "org.bouncycastle" % "bcprov-jdk15on" % "1.58" % "provided",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.58" % "provided",
  "com.typesafe" % "config" % "1.3.1",
  "org.scalatest" %% "scalatest" % "3.0.4" % "test"
)

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

homepage := Some(url(s"https://github.com/Karasiq/${name.value}"))

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