package scalatra.service

import java.security.MessageDigest
import java.util.Base64

import org.json4s.native.JsonMethods._
import org.json4s.native.Serialization.write
import org.json4s.{DefaultFormats, Formats}
import org.scalatra._
import org.scalatra.json._

import scala.collection.mutable
import scalatra.service.Data._
import scalatra.service.Types._

object Types {
  type Timestamp = Long
  type UserID = Int
  type TwitID = Int
  type ID = Int
}

object Data {
  var users: mutable.HashMap[UserID, User] = mutable.HashMap[UserID, User]()
  var valid_tokens: mutable.HashMap[String, JWToken] = mutable.HashMap[String, JWToken]()
  var twits: mutable.HashMap[TwitID, _Twit] = mutable.HashMap[TwitID, _Twit]()
  val one_day: Timestamp = 1000 * 60 * 60 * 24
}

case class MessageString(text: String)

class User(val id: UserID,
           val email: String,
           var nick: String,
           var pswd: String,
           var twits: mutable.HashSet[TwitID] = mutable.HashSet[TwitID](),
           var subscribed: mutable.HashSet[UserID] = mutable.HashSet[UserID]()) {

}

object User {
  val md: MessageDigest = {
    MessageDigest.getInstance("SHA-1")
  }

  def hash(s: String): String = {
    md.digest(s.toCharArray.map(_.toByte))
      .map("%02X" format _)
      .mkString
  }
}

class _Twit(val id: TwitID,
            var text: String,
            val author: UserID,
            val submitted: Timestamp,
            var parent: Option[TwitID] = None,
            var retwits: mutable.HashSet[TwitID] = mutable.HashSet[TwitID](),
            var updated: Option[Timestamp] = None) {
  def toCase: Twit = {
    Twit(id, text, author, submitted, parent.getOrElse(-1), updated.getOrElse(-1))
  }
}

case class Twit(id: TwitID,
                text: String,
                author: UserID,
                submitted: Timestamp,
                parent: TwitID,
                updated: Timestamp)

case class Credentials(email: String, pswd: String, nick: Option[String] = None)

case class Error(msg: String)

case class JWTHeader(alg: String = "HMAC_MD5", typ: String = "JWT")

case class JWTPayload(id: UserID, timestamp: Timestamp, exp: Timestamp = one_day)

case class Token(token: String)

case class Id(id: ID)

class JWToken(val payload: JWTPayload, val pass: String) {

  def hmac_md5(K: String, D: String): String = {
    def hash(s: String): String = {
      JWToken.md.digest(s.toCharArray.map(_.toByte))
        .map("%02X" format _)
        .mkString
    }

    hash(K + hash(K + D))
  }

  def toCase: Token = {
    val load = write(payload)
    val header_encoded = Base64.getUrlEncoder.encodeToString(write(JWTHeader()).getBytes)
    val payload_encoded = Base64.getUrlEncoder.encodeToString(load.getBytes)
    Token(header_encoded
      + "."
      + payload_encoded
      + "."
      + hmac_md5(pass, header_encoded + "." + payload_encoded))
  }

  protected implicit lazy val jsonFormats: Formats = DefaultFormats
}

object JWToken {
  val md: MessageDigest = {
    MessageDigest.getInstance("MD5")
  }

  def checkToken(token: String): Boolean = {
    if (valid_tokens.contains(token)) {
      val payload = extractPayload(token)
      if (payload.timestamp + payload.exp < System.currentTimeMillis()) {
        valid_tokens.remove(token)
        false
      }
      else {
        true
      }
    }
    else {
      false
    }
  }

  def getUserId(token: String): UserID = {
    extractPayload(token).id
  }

  def extractPayload(token: String): JWTPayload = {
    parse(Base64
      .getUrlDecoder
      .decode(token.split("\\.")(1))
      .map(_.toChar)
      .mkString)
      .extract[JWTPayload]
  }

  protected implicit lazy val jsonFormats: Formats = DefaultFormats

}

class MessageServlet extends ScalatraServlet with JacksonJsonSupport {

  post("/register/?") {
    val credentials = parsedBody.extract[Credentials]
    if (users.values.exists(_.email == credentials.email)) {
      Forbidden(Error("User with this email already exists."))
    }
    else {
      val new_id = if (users.nonEmpty) users.values.maxBy(_.id).id + 1 else 1
      users += new_id -> new User(new_id,
        credentials.email,
        if (credentials.nick.nonEmpty)
          credentials.nick.get
        else
          credentials.email.split("@")(0),
        User.hash(credentials.pswd))
      users(new_id).subscribed += new_id
      Ok()
    }
  }

  post("/login/?") {
    val credentials = parsedBody.extract[Credentials]
    val candidate = users.values.find(_.email == credentials.email)
    if (candidate.nonEmpty) {
      if (candidate.get.pswd == User.hash(credentials.pswd)) {
        val token = new JWToken(
            JWTPayload(candidate.get.id,
            System.currentTimeMillis()),
            credentials.pswd)
        val serialised = token.toCase
        valid_tokens += serialised.token -> token
        Ok(serialised)
      }
      else {
        Forbidden(Error("Invalid email or password"))
      }
    }
    else {
      Forbidden(Error("Invalid email or password"))
    }
  }

  get("/logout/?") {
    val our_token = valid_tokens.get(params("token"))
    if (our_token.isEmpty) {
      //If the user is unathorized, there is nothing bad if we just return success
      //There is nothing else to do
      //Why return error, when no access violation occurs?
      Ok()
    } else {
      valid_tokens -= our_token.get.toCase.token
      Ok()
    }
  }

  post("/twit/?") {
    if (!JWToken.checkToken(params("token"))) {
      Forbidden(Error("Log in to create twits"))
    }
    else {
      val time = System.currentTimeMillis()
      val new_id = if (twits.nonEmpty) twits.values.maxBy(_.id).id + 1 else 1
      val userid = JWToken.getUserId(params("token"))
      val new_twit = new _Twit(new_id,
        parsedBody.extract[MessageString].text,
        userid,
        time)
      twits += new_id -> new_twit
      users(userid).twits += new_id
      Ok(Id(new_id))
    }
  }

  put("/twit/?") {
    if (!JWToken.checkToken(params("token"))) {
      Forbidden(Error("Log in to edit twits"))
    }
    else {
      val time = System.currentTimeMillis()
      val twit_id = params("id").toInt
      if (twits.get(twit_id).isEmpty) {
        NotFound()
      }
      else {
        val userid = JWToken.getUserId(params("token"))
        if (!users(userid).twits.contains(twit_id)) {
          Forbidden(Error("You only can edit your own twits"))
        }
        else {
          val twit = twits(twit_id)
          if (twit.parent.isEmpty) {
            if (twit.retwits.isEmpty) {
              twit.text = parsedBody.extract[MessageString].text
              twit.updated = Some(time)
              twits.update(twit_id, twit)
              Ok()
            }
            else {
              Forbidden(Error("You cannot edit retwitted twits."))
            }
          }
          else {
            Forbidden(Error("You cannot edit retwits."))
          }
        }
      }
    }
  }

  get("/twit/?") {
    val twit_id = params("id").toInt
    if (twits.get(twit_id).isEmpty) {
      NotFound()
    }
    else {
      Ok(write(twits(twit_id).toCase))
    }
  }

  delete("/twit/?") {
    if (!JWToken.checkToken(params("token"))) {
      Forbidden(Error("Log in to delete twits"))
    }
    else {
      val twit_id = params("id").toInt
      if (twits.get(twit_id).isEmpty) {
        NotFound()
      }
      else {
        val userid = JWToken.getUserId(params("token"))
        if (!users(userid).twits.contains(twit_id)) {
          Forbidden(Error("You only can delete your own twits"))
        }
        else {
          twits.filter(_._2.parent.contains(twit_id))
               .foreach((f: (TwitID, _Twit)) => {
                 twits -= f._1
                 users(f._2.author).twits -= f._1
               })
          users(userid).twits -= twit_id
          twits.remove(twit_id)
          Ok()
        }
      }
    }
  }

  post("/subscribe/?") {
    if (!JWToken.checkToken(params("token"))) {
      Forbidden(Error("Log in to subscribe"))
    }
    else {
      if (users.get(params("id").toInt).isEmpty) {
        NotFound()
      }
      else {
        users(JWToken.getUserId(params("token"))).subscribed += params("id").toInt
        Ok()
      }
    }
  }

  get("/feed/my/?") {
    if (!JWToken.checkToken(params("token"))) {
      Forbidden(Error("Log in to see your feed"))
    }
    else {
      val all_twits_ids = users(JWToken.getUserId(params("token")))
        .subscribed
        .flatMap(users(_).twits)
      val retwits = twits
        .clone()
        .filter(
          (p: (TwitID, _Twit)) =>
            p._2.parent.nonEmpty && all_twits_ids.contains(p._2.parent.get))
        .keys
      Ok(write((all_twits_ids ++ retwits)
        .map(twits(_).toCase)
        .toList
        .sortBy(_.submitted)))
    }
  }

  // not sure if we need this
  //  get("/twits/:id/:token") {
  //    if (users.get(params("id").toInt).isEmpty) {
  //      NotFound()
  //    }
  //    else {
  //      Ok(users(params("id").toInt).twits.map(twits(_).toCase()))
  //    }
  //  }

  get("/twits/?") {
    if (users.get(params("id").toInt).isEmpty) {
      NotFound()
    }
    else {
      Ok(users(params("id").toInt).twits.map(twits(_).toCase).toList)
    }
  }

  post("/retwit/?") {
    if (!JWToken.checkToken(params("token"))) {
      Forbidden(Error("Log in to subscribe"))
    }
    else {
      val time = System.currentTimeMillis()
      val twit_id = params("id").toInt
      if (twits.get(twit_id).isEmpty) {
        NotFound()
      }
      else {
        val new_id = if (twits.nonEmpty) twits.values.maxBy(_.id).id + 1 else 1
        val userid = JWToken.getUserId(params("token"))
        val retweet = new _Twit(new_id,
          twits(twit_id).text,
          userid,
          time,
          Some(if (twits(twit_id).parent.isEmpty) twit_id else twits(twit_id).parent.get))
        twits += new_id -> retweet
        twits(twit_id).retwits += new_id
        users(userid).twits += new_id
        Ok(write(retweet.toCase))
      }
    }
  }

  before() {
    contentType = formats("json")
  }

  protected implicit lazy val jsonFormats: Formats = DefaultFormats
}

