package scalatra.service

import org.scalatra._

import scala.collection.mutable
import org.json4s.{DefaultFormats, Formats}
import org.scalatra.json._

class MessageServlet extends ScalatraServlet with JacksonJsonSupport {

  var storage: mutable.HashMap[Int, Message] = mutable.HashMap[Int, Message]()

  post("/messages/") {
    val msg = parsedBody.extract[Message]
    storage += msg.id -> msg
    Ok()
  }

  get("/messages/") {
    Ok(storage.values)
  }

  get("/messages/:id") {
    val id = params("id").toInt
    if (storage.contains(id))
      Ok(storage(id))
    else
      NotFound("Sorry, there's no message with such ID")
  }

  put("/messages/:id") {
    val msg = parsedBody.extract[MessageString]
    val id = params("id").toInt
    if (storage.contains(id)) {
      storage(id) = Message(id, msg.text)
      Ok()
    }
    else
      NotFound("Sorry, there's no message with such ID")
  }

  delete("/messages/:id") {
    storage -= params("id").toInt
    Ok()
  }

  before() {
    contentType = formats("json")
  }

  protected implicit lazy val jsonFormats: Formats = DefaultFormats
}

case class Message(id: Int, text: String)

case class MessageString(text: String)