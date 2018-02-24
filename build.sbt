val ScalatraVersion = "2.6.2"

organization := "Innopolis"

name := "Tiny Message Web Server"

version := "0.1.0"

scalaVersion := "2.12.1"

resolvers += Classpaths.typesafeReleases

libraryDependencies ++= Seq(
  "org.scalatra" %% "scalatra" % ScalatraVersion,
  "org.scalatra" %% "scalatra-scalatest" % ScalatraVersion % "test",
  "ch.qos.logback" % "logback-classic" % "1.2.3" % "runtime",
  "org.eclipse.jetty" % "jetty-webapp" % "9.4.8.v20171121" % "container",
  "javax.servlet" % "javax.servlet-api" % "3.1.0" % "provided",
  "org.scalatra" %% "scalatra-json" % ScalatraVersion,
  "org.json4s"   %% "json4s-jackson" % "3.5.3",
  "org.json4s" %% "json4s-native" % "3.5.3",
  "commons-codec" % "commons-codec" % "1.11"
)

enablePlugins(SbtTwirl)
enablePlugins(ScalatraPlugin)
