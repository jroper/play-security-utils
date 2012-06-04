package play.api.security.utils

import play.api.test.FakeApplication
import org.specs2.mutable.Specification
import org.specs2.specification.Scope
import play.api.mvc.Session
import play.api.security.utils.SecureSession.convertSecureSession
import play.api.test.Helpers._

case class SecureSessionSpec() extends Specification {
  sequential
  "SecureSession token verification" should {

    "put the token in session" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token").get("key" + SecureSession.TOKEN_SUFFIX) must_!= None
      }
    }
    "hash the token when it puts it in the session" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token").get("key" + SecureSession.TOKEN_SUFFIX) must_!= Some("token")
      }
    }
    "verify the hashed token when getting a value verified by the token" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token").getVerifiedByToken("key") {
          value: String => Some("token")
        } must_== Some("value")
      }
    }
    "fail verification of hashed token when token changes" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token").getVerifiedByToken("key") {
          value: String => Some("foo")
        } must_== None
      }
    }
    "fail verification of hashed token when no token found for value" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token").getVerifiedByToken("key") {
          value: String => None
        } must_== None
      }
    }
    "fail verification of hashed token when no hashed token supplied" in new Setup {
      running(fakeApp) {
        val sessionWithoutToken = session + ("key", "value")
        sessionWithoutToken.getVerifiedByToken("key") {
          value: String => Some("token")
        } must_== None
      }
    }
    "remove value and token when value is removed" in new Setup {
      running(fakeApp) {
        val result = session.putWithToken("key", "value", "token").removeWithToken("key")
        result.get("key") must_== None
        result.get("key" + SecureSession.TOKEN_SUFFIX) must_== None
      }
    }
    "not hash the token when requested" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token", hashToken = false)
          .get("key" + SecureSession.TOKEN_SUFFIX) must_== Some("token")
      }
    }
    "verify the unhashed token when getting a value verified by the token" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token", hashToken = false).getVerifiedByToken("key", hashToken=false) {
          value: String => Some("token")
        } must_== Some("value")
      }
    }
    "fail verification of unhashed token when getting a value verified by the token" in new Setup {
      running(fakeApp) {
        session.putWithToken("key", "value", "token", hashToken = false).getVerifiedByToken("key", hashToken=false) {
          value: String => Some("foo")
        } must_== None
      }
    }
  }

  "SecureSession sensitive attributes" should {

    "encrypt a sensitive value" in new Setup {
      running(fakeApp) {
        session.putSensitive("key", "value").get("key") must_!= Some("value")
      }
    }
    "decrypt a sensitive value" in new Setup {
      running(fakeApp) {
        session.putSensitive("key", "value").getSensitive("key") must_== Some("value")
      }
    }

  }

  trait Setup extends Scope {
    val fakeApp = FakeApplication(additionalConfiguration = Map(
      "ehcacheplugin" -> "disabled",
      "application.secret" -> "secret"))
    val session = new Session()
  }
}

