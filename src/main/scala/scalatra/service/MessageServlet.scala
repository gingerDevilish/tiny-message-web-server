package scalatra.service

import java.security.MessageDigest
import java.util.Base64

import org.json4s.native.Serialization.write
import org.json4s.{DefaultFormats, Formats}
import org.scalatra._
import org.scalatra.json._

import scala.collection.mutable

case class MessageString(text: String)

class User(val id: Int,
           val email: String,
           var nick: String,
           var pswd: String,
           var twits: mutable.HashSet[Int] = mutable.HashSet[Int](),
           var subscribed: mutable.HashSet[Int] = mutable.HashSet[Int]()) {

}

class _Twit(val id: Int,
            var text: String,
            val author: Int,
            val submitted: Long,
            var parent: Option[Int] = None,
            var retwits: mutable.HashSet[Int] = mutable.HashSet[Int](),
            var updated: Option[Long] = None) {
  def toCase: Twit = {
    Twit(id, text, author, submitted, parent, updated)
  }
}

case class Twit(id: Int,
                text: String,
                author: Int,
                submitted: Long,
                retwit: Option[Int] = None,
                updated: Option[Long] = None)

case class Credentials(email: String, pswd: String, nick: Option[String] = None)

case class Error(msg: String)

case class JWTHeader(alg: String = "HMAC_MD5", typ: String = "JWT")

case class JWTPayload(id: Int, timestamp: Long, exp: Long = 1000 * 60 * 60 * 24)

case class Token(token: String)

class MessageServlet extends ScalatraServlet with JacksonJsonSupport {

  var users: mutable.HashMap[Int, User] = mutable.HashMap[Int, User]()
  val md: MessageDigest = {
    MessageDigest.getInstance("MD5")
  }
  var valid_tokens: mutable.HashSet[Token] = mutable.HashSet[Token]()
  var twits: mutable.HashMap[Int, _Twit] = mutable.HashMap[Int, _Twit]()

  def hmac_md5(K: String, D: String): String = {
    def hash(s: String): String = {
      md.digest(s.toCharArray.map(_.toByte))
        .map("%02X" format _)
        .mkString
    }

    hash(K+hash(K+D))
  }

  def checkToken(token: String): Boolean = {
    if (valid_tokens.contains(Token(token))) {
      if (extractPayload(token).exp < System.currentTimeMillis()) {
        valid_tokens.remove(Token(token))
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

  def getUserId(token: String): Int = {
    extractPayload(token).id
  }

  def extractPayload(token: String): JWTPayload = {
    parse(Base64
      .getUrlDecoder
      .decode(token.split(".")(1))
      .map(_.toChar)
      .mkString)
      .extract[JWTPayload]
  }

  post("/register/") {
    val credentials = parsedBody.extract[Credentials]
    if (users.values.exists(_.email == credentials.email)) {
      Forbidden(Error("User with this email already exists."))
    }
    else {
      val max_id = users.values.maxBy(_.id).id
      users += (max_id + 1) -> new User(max_id + 1,
        credentials.email,
        if (credentials.nick.nonEmpty)
          credentials.nick.get
        else
          credentials.email.split("@")(0),
        credentials.pswd)
      users(max_id + 1).subscribed += (max_id + 1)
      Ok()
    }
  }

  post("/login/") {
    val credentials = parsedBody.extract[Credentials]
    val candidate = users.values.find(_.email == credentials.email)
    if (candidate.nonEmpty) {
      if (candidate.get.pswd == credentials.pswd) {
        val payload = write(JWTPayload(candidate.get.id, System.currentTimeMillis()))
        val header_encoded = Base64.getUrlEncoder.encode(write(JWTHeader()).getBytes)
        val payload_encoded = Base64.getUrlEncoder.encode(payload.getBytes)
        val token = Token(header_encoded
                    + "."
                    + payload_encoded
                    + "."
                    + hmac_md5(credentials.pswd, header_encoded + "." + payload_encoded))
        valid_tokens += token
        Ok(token)
      }
      else {
        Forbidden(Error("Invalid email or password"))
      }
    }
    else {
      Forbidden(Error("Invalid email or password"))
    }
  }

  get("/logout/:token") {
    val our_token = valid_tokens.find(_.token == params("token"))
    if (our_token.isEmpty) {
      Ok()
    } else {
      valid_tokens -= our_token.get
      Ok()
    }
  }

  post("/twit/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to create twits"))
    }
    else {
      val time = System.currentTimeMillis()
      val maxid = twits.values.maxBy(_.id).id
      val userid = getUserId(params("token"))
      twits += (maxid + 1) -> new _Twit(maxid + 1,
                  parsedBody.extract[MessageString].text,
                  userid,
                  time)
      users(userid).twits += maxid + 1
      Ok()
    }
  }

  put("/twit/:id/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to edit twits"))
    }
    else {
      val time = System.currentTimeMillis()
      val twit_id = params("id").toInt
      if (twits.get(twit_id).isEmpty) {
        NotFound()
      }
      else {
        val userid = getUserId(params("token"))
        if (users(userid).twits.contains(twit_id)) {
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

  delete("/twit/:id/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to delete twits"))
    }
    else {
      val twit_id = params("id").toInt
      if (twits.get(twit_id).isEmpty) {
        NotFound()
      }
      else {
        val userid = getUserId(params("token"))
        if (!users(userid).twits.contains(twit_id)) {
          Forbidden(Error("You only can delete your own twits"))
        }
        else {
          val retwits = twits.clone()
          retwits.filter(_._2.parent.contains(twit_id))
          retwits.foreach((f: (Int, _Twit)) => users(f._2.author).twits -= f._1)
          twits --= retwits.keys
          users(userid).twits -= twit_id
          twits.remove(twit_id)
          Ok()
        }
      }
    }
  }

  post("/subscribe/:id/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to subscribe"))
    }
    else {
      if (users.get(params("id").toInt).isEmpty) {
        NotFound()
      }
      else {
        users(getUserId(params("token"))).subscribed += params("id").toInt
        Ok()
      }
    }
  }

  get("/feed/my/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to see your feed"))
    }
    else {
      var all_twits_ids = new mutable.HashSet[Int]()
      users(getUserId(params("token")))
        .subscribed
        .foreach(all_twits_ids ++= users(_).twits)
      val retwits = twits
        .clone()
        .filter(
          (p: (Int, _Twit)) =>
            p._2.parent.nonEmpty && all_twits_ids.contains(p._2.parent.get))
        .keys
      Ok((all_twits_ids ++ retwits)
        .map(twits(_).toCase)
        .toList
        .sortBy(_.submitted))
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

  get("/twits/:id") {
    if (users.get(params("id").toInt).isEmpty) {
      NotFound()
    }
    else {
      Ok(users(params("id").toInt).twits.map(twits(_).toCase))
    }
  }

  post("/retwit/:id/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to subscribe"))
    }
    else {
      val time = System.currentTimeMillis()
      val twit_id = params("id").toInt
      if (twits.get(twit_id).isEmpty) {
        NotFound()
      }
      else {
        val max_id = twits.values.maxBy(_.id).id
        val userid = getUserId(params("token"))
        twits += (max_id + 1) -> new _Twit(max_id + 1,
          twits(twit_id).text,
          userid,
          time,
          Some(twit_id))
        twits(twit_id).retwits += max_id + 1
        users(userid).twits += max_id + 1
        Ok()
      }
    }
  }

  before() {
    contentType = formats("json")
  }

  protected implicit lazy val jsonFormats: Formats = DefaultFormats
}

