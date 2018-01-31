package scalatra.service

import org.scalatra.test.scalatest._

class MessageServletTests extends ScalatraFunSuite {

  addServlet(classOf[MessageServlet], "/*")

  test("GET / on MessageServlet should return status 200"){
    get("/"){
      status should equal (200)
    }
  }

}
