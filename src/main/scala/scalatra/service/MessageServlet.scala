package scalatra.service

import java.security.MessageDigest
import java.util.Base64

import org.scalatra._

import scala.collection.mutable
import org.json4s.{DefaultFormats, Formats}
import org.scalatra.json._
import org.json4s.native.Serialization.{read, write}

import scala.collection.mutable.ListBuffer
import scala.util.parsing.json.JSON

case class Message(id: Int, text: String)

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
  def toCase(): Twit = {
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

  var storage = mutable.HashMap[Int, Message]()
  var users: mutable.HashMap[Int, User] = mutable.HashMap[Int, User]()
  val md = MessageDigest.getInstance("MD5")
  var valid_tokens = mutable.HashSet[Token]()
  var twits = mutable.HashMap[Int, _Twit]()

  def hmac_md5(K: String, D: String): String = {
    val bytes = (K + D).toCharArray.map(_.toByte)
    val temp = (K + md.digest(bytes).map("%02X" format _).mkString).toCharArray.map(_.toByte)
    md.digest(temp).map("%02X" format _).mkString
  }

  // TODO get rid of token storage - can check signature instead
  def checkToken(token: String): Boolean = {
    if (valid_tokens.contains(Token(token))) {
      val body = parse(Base64.getUrlDecoder().decode(token.split(".")(1))
        .map(_.toChar).mkString).extract[JWTPayload]
      if (body.exp < System.currentTimeMillis()) {
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
    parse(Base64.getUrlDecoder().decode(token.split(".")(1))
      .map(_.toChar).mkString).extract[JWTPayload].id
  }

  post("/register/") {
    val credentials = parsedBody.extract[Credentials]
    if (users.values.find((v: User) => v.email == credentials.email).nonEmpty) {
      Forbidden(Error("User with this email already exists."))
    }
    else {
      val max_id = users.values.maxBy((x: User) => x.id).id
      val nickname: String = if (credentials.nick.nonEmpty) credentials.nick.get
      else credentials.email.split("@")(0)
      users += (max_id + 1) -> new User(max_id + 1,
        credentials.email,
        nickname,
        credentials.pswd)
      users(max_id + 1).subscribed += (max_id + 1)
      Ok()
    }
  }

  post("/login/") {
    val credentials = parsedBody.extract[Credentials]
    val candidate = users.values.find((v: User) => v.email == credentials.email)
    if (candidate.nonEmpty) {
      if (candidate.get.pswd == credentials.pswd) {
        val header = write(JWTHeader())
        val payload = write(JWTPayload(candidate.get.id, System.currentTimeMillis()))
        val header_encoded = Base64.getUrlEncoder.encode(header.getBytes)
        val payload_encoded = Base64.getUrlEncoder.encode(payload.getBytes)
        val signature = hmac_md5(credentials.pswd, header_encoded + "." + payload_encoded)
        val token = Token(header_encoded + "." + payload_encoded + "." + signature)
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
    val our_token = valid_tokens.find((p: Token) => p.token == params("token"))
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
      // proceed with creating twits
      val time = System.currentTimeMillis()
      val text = parsedBody.extract[MessageString]
      val maxid = twits.values.maxBy((x: _Twit) => x.id).id
      val userid = getUserId(params("token"))
      twits += (maxid + 1) -> new _Twit(maxid + 1, text.text, userid, time)
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
      if (twits.get(params("id").toInt).isEmpty) {
        NotFound()
      }
      else {
        val userid = getUserId(params("token"))
        if (users(userid).twits.find(_ == params("id").toInt).isEmpty) {
          Forbidden(Error("You only can edit your own twits"))
        }
        else {
          val twit = twits.get(params("id").toInt).get
          twit.text = parsedBody.extract[MessageString].text
          twit.updated = Some(time)
          twits.update(params("id").toInt, twit)
          Ok()
        }
      }
    }
  }

  delete("/twit/:id/:token") {
    if (!checkToken(params("token"))) {
      Forbidden(Error("Log in to delete twits"))
    }
    else {
      if (twits.get(params("id").toInt).isEmpty) {
        NotFound()
      }
      else {
        val userid = getUserId(params("token"))
        if (users(userid).twits.find(_ == params("id").toInt).isEmpty) {
          Forbidden(Error("You only can delete your own twits"))
        }
        else {
          users(userid).twits -= params("id").toInt
          twits.remove(params("id").toInt)
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
      if(users.get(params("id").toInt).isEmpty) {
        NotFound()
      }
      else {
        val userid = getUserId(params("token"))
        users(userid).subscribed += params("id").toInt
        Ok()
      }
    }
  }

  get("/feed/my/:token") {
    if(!checkToken(params("token"))) {
      Forbidden(Error("Log in to see your feed"))
    }
    else {
      val userid = getUserId(params("token"))
      var all_twits_ids = new ListBuffer[Int]()
      users(userid).subscribed.foreach((x: Int) => all_twits_ids ++= users(x).twits)
      var all_twits = all_twits_ids.map((x: Int) => twits(x).toCase()).sortBy(_.submitted)
      Ok(all_twits)
    }
  }

  get("/twits/:id/:token") {
    if (users.get(params("id").toInt).isEmpty) {
      NotFound()
    }
    else {
      Ok(users(params("id").toInt).twits.map(twits(_).toCase()))
    }
  }

  get("/twits/:id") {
    if (users.get(params("id").toInt).isEmpty) {
      NotFound()
    }
    else {
      Ok(users(params("id").toInt).twits.map(twits(_).toCase()))
    }
  }

  post("/retwit/:id/:token") {
    if(!checkToken(params("token"))) {
      Forbidden(Error("Log in to subscribe"))
    }
    else {
      val time = System.currentTimeMillis()
      if (twits.get(params("id").toInt).isEmpty) {
        NotFound()
      }
      else {
        val max_id = twits.values.maxBy((x: _Twit) => x.id).id
        val userid = getUserId(params("token"))
        twits += (max_id+1) -> new _Twit(max_id+1, )
        //
      }
    }
  }

  before() {
    contentType = formats("json")
  }

  protected implicit lazy val jsonFormats: Formats = DefaultFormats
}

