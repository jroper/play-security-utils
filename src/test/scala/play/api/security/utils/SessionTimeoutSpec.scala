package play.api.security.utils

import org.specs2.mutable.Specification
import play.api.test.FakeApplication
import org.specs2.specification.Scope
import play.api.security.utils.SessionTimeoutMode._
import play.api.mvc._
import play.api.test.Helpers._
import play.api.http.HeaderNames
import SessionTimeoutConfig._
import play.api.libs.concurrent.Promise

class SessionTimeoutSpec extends Specification with Results {
  sequential
  "Session timeout action" should {
    "do nothing with the session when no session exists and no session is created" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest) { request =>
          NoContent
        }
        result.header.headers.isEmpty must_== true
      }
    }
    "add a timeout to the session when a session is created" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest) { request =>
          NoContent.withSession("a" -> "b")
        }
        val session = decodeSession(result)
        session.get("a") must_== Some("b")
        session.get(sessionTimestampKey).isDefined must_== true
      }
    }
    "allow a session if not expired" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (System.currentTimeMillis() - 10000).toString))
        )) { request =>
          request.session.get(sessionTimestampKey).isDefined must_== true
          NoContent
        }
        result.header.headers.isEmpty must_== true
      }
    }
    "end a session if expired" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (System.currentTimeMillis() - 7300000).toString))
        )) { request =>
          request.session.isEmpty must_== true
          NoContent
        }
        val cookie = result.header.headers.get(HeaderNames.SET_COOKIE)
          .flatMap(value => Cookies.decode(value).find(_.name == Session.COOKIE_NAME))
        cookie.isDefined must_== true
        cookie.get.value must_== ""
      }
    }
    "end a session if it contains no timestamp" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest(
          new Session(Map("a" -> "b"))
        )) { request =>
          request.session.isEmpty must_== true
          NoContent
        }
        val cookie = result.header.headers.get(HeaderNames.SET_COOKIE)
          .flatMap(value => Cookies.decode(value).find(_.name == Session.COOKIE_NAME))
        cookie.isDefined must_== true
        cookie.get.value must_== ""
      }
    }
    "allow a new session to be created when the old session is expired" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (System.currentTimeMillis() - 7300000).toString))
        )) { request =>
          request.session.isEmpty must_== true
          NoContent.withSession("a" -> "b")
        }
        decodeSession(result).get("a") must_== Some("b")
      }
    }
    "set a timestamp on a new session when the old has expired" in new Setup {
      running(fakeApp) {
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (System.currentTimeMillis() - 7300000).toString))
        )) { request =>
          request.session.isEmpty must_== true
          NoContent.withSession("a" -> "b")
        }
        decodeSession(result).get(sessionTimestampKey).isDefined must_== true
      }
    }
    "update the timestamp in last accessed mode, preserving existing session" in new Setup {
      running(fakeApp) {
        val t = System.currentTimeMillis() - 400000
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (t).toString,
                          "a" -> "b"
          ))
        ), LastAccessed) { request =>
          NoContent
        }
        val session = decodeSession(result)
        session.get("a") must_== Some("b")
        session.get(sessionTimestampKey).isDefined must_== true
        session.get(sessionTimestampKey) must_!= Some(t.toString)
      }
    }
    "update the timestamp in last accessed mode, preserving newly set session" in new Setup {
      running(fakeApp) {
        val t = System.currentTimeMillis() - 400000
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (t).toString))
        ), LastAccessed) { request =>
          NoContent.withSession("a" -> "b")
        }
        val session = decodeSession(result)
        session.get("a") must_== Some("b")
        session.get(sessionTimestampKey).isDefined must_== true
        session.get(sessionTimestampKey) must_!= Some(t.toString)
      }
    }
    "only after a delay update the timestamp in last accessed mode" in new Setup {
      running(fakeApp) {
        val t = System.currentTimeMillis() - 200000
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (t).toString))
        ), LastAccessed) { request =>
          NoContent
        }
        result.header.headers.isEmpty must_== true
      }
    }
    "not revive the session in last accessed mode if the session is cleared" in new Setup {
      running(fakeApp) {
        val t = System.currentTimeMillis() - 400000
        val result = test(new FakeRequest(
          new Session(Map(sessionTimestampKey -> (t).toString))
        ), LastAccessed) { request =>
          NoContent.withNewSession
        }
        val session = decodeSession(result)
        session.isEmpty must_== true
      }
    }
    "map logic to result promise when an async result is returned" in new Setup {
      val result = test(new FakeRequest(
        new Session(Map(sessionTimestampKey -> (System.currentTimeMillis() - 7300000).toString))
      )) { request =>
        new AsyncResult(Promise.pure(NoContent))
      }
      val cookie = result.header.headers.get(HeaderNames.SET_COOKIE)
        .flatMap(value => Cookies.decode(value).find(_.name == Session.COOKIE_NAME))
      cookie.isDefined must_== true
      cookie.get.value must_== ""
    }
  }

  trait Setup extends Scope {
    val fakeApp = FakeApplication(additionalConfiguration = Map(
      "ehcacheplugin" -> "disabled",
      "application.secret" -> "secret"))

    def test(request: Request[AnyContent], mode: SessionTimeoutMode = MaxLength)(action: Request[AnyContent] => Result): PlainResult = {
      SessionTimeout(mode = mode) {
        Action { request =>
          action(request)
        }
      }.apply(request) match {
        case plain: PlainResult => plain
        case async: AsyncResult => async.result.await.get.asInstanceOf[PlainResult]
      }
    }

    def decodeSession(result: PlainResult): Session = {
      Session.decodeFromCookie(result.header.headers.get(HeaderNames.SET_COOKIE)
        .flatMap(value => Cookies.decode(value).find(_.name == Session.COOKIE_NAME)))
    }
  }

}
