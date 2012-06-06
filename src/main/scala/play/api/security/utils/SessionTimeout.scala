package play.api.security.utils

import SessionTimeoutConfig._
import SessionTimeoutMode._
import util.control.Exception._
import util.Random
import play.api.mvc._
import play.api.http.HeaderNames
import play.api.http.HeaderNames._

/**
 * Provides a session timeout.
 */
case class SessionTimeout[A](mode: SessionTimeoutMode = sessionTimeoutMode,
                                   timeoutSecs: Int = sessionTimeoutSecs,
                                   updateIntervalSecs: Int = lastAccessedUpdateIntervalSecs)
                                  (val action: Action[A]) extends Action[A] {
  private val rand = new Random

  override def apply(request: Request[A]): Result = {
    // Calculate the timestamp
    val timestamp = request.session.get(sessionTimestampKey) flatMap { value =>
      catching(classOf[NumberFormatException]) opt (value.toLong)
    }
    // Calculate whether the incoming session is expired
    val expired = timestamp map { value =>
      (System.currentTimeMillis() - timeoutSecs * 1000) > value
    } getOrElse false
    // We should block the incoming session if it is expired, or if there is a session but no timestamp is defined
    val blockSession = expired || (!request.session.isEmpty && !timestamp.isDefined)

    // Block the session if necessary
    var wrappedRequest = request
    if (blockSession) {
      wrappedRequest = new WrappedRequest(request) {
        override lazy val session = new Session
      }
    }

    handleResult(action.apply(wrappedRequest), timestamp, blockSession, request.session)
  }

  private def handleResult(result: Result,
                           timestamp: Option[Long],
                           blockSession: Boolean,
                           incomingSession: Session) : Result = {
    result match {
      case async: AsyncResult => new AsyncResult(async.result.map(result =>
        handleResult(result, timestamp, blockSession, incomingSession)))
      case plain: PlainResult => handlePlainResult(plain, timestamp, blockSession, incomingSession)
    }
  }

  private def handlePlainResult(result: PlainResult,
                                timestamp: Option[Long],
                                blockSession: Boolean,
                                incomingSession: Session) : Result = {
    // Decode the cookies
    val cookies = result.header.headers.get(HeaderNames.SET_COOKIE).map(value => Cookies.decode(value))
    // Find the session
    val sessionCookie = cookies.flatMap(_.find(_.name == Session.COOKIE_NAME))
    val session = Session.decodeFromCookie(sessionCookie)

    // If there is a session cookie, but the session is empty, then the session has been unset, so no need to do
    // anything
    if (sessionCookie.isDefined && session.isEmpty) {
      return result
    }

    // If we need to block the session, and there's no new session, then we need discard the session cookie
    if (blockSession && session.isEmpty) {
      return discardingCookies(result, Session.COOKIE_NAME)
    }

    // If there's a new session (ie, no timestamp set in it) we need to add it.
    if (!session.isEmpty && session.get(sessionTimestampKey).isEmpty) {
      return withSession(result, session + (sessionTimestampKey -> System.currentTimeMillis().toString))
    }

    // Only need to do something now if in last accessed mode, and it's time to update the timestamp
    if (mode == LastAccessed && shouldUpdate(timestamp)) {
      // If there's a session set in the result, update the timestamp in that
      if (!session.isEmpty) {
        return withSession(result, session + (sessionTimestampKey -> System.currentTimeMillis().toString))
      }
      // Otherwise, set the timestamp from the incoming session
      return withSession(result, incomingSession + (sessionTimestampKey -> System.currentTimeMillis().toString))
    }

    // Nothing to do
    result
  }

  /*
   * The methods below all serve to work around bug #511. They are copies of the corresponding methods on Result
   * and Cookies, and ensure that the result ends up with unique cookie values.
   */
  private def withSession(result: PlainResult, session: Session): PlainResult = {
    if (session.isEmpty) discardingCookies(result, Session.COOKIE_NAME) else withCookies(result, Session.encodeAsCookie(session))
  }

  private def withCookies(result: PlainResult, cookies: Cookie*): PlainResult = {
    result.withHeaders(SET_COOKIE -> mergeCookies(result.header.headers.get(SET_COOKIE).getOrElse(""), cookies))
  }

  private def discardingCookies(result: PlainResult, names: String*): PlainResult = {
    result.withHeaders(SET_COOKIE -> mergeCookies(result.header.headers.get(SET_COOKIE).getOrElse(""), Nil, discard = names))
  }

  private def mergeCookies(cookieHeader: String, cookies: Seq[Cookie], discard: Seq[String] = Nil): String = {
    val existing = Cookies.decode(cookieHeader) filterNot { cookie =>
      cookies.exists(_.name == cookie.name) || discard.contains(cookie.name)
    }
    Cookies.encode(existing ++ cookies, discard)
  }
  /*
   * End work around methods
   */

  private def shouldUpdate(timestamp: Option[Long]): Boolean = {
    timestamp map { value =>
      mode == LastAccessed  &&
        (System.currentTimeMillis() - lastAccessedUpdateIntervalSecs * 1000 - rand.nextInt(10000)) > value
    } getOrElse false
  }

  lazy val parser = action.parser
}

object SessionTimeoutHandler {
  def apply(mode: SessionTimeoutMode = sessionTimeoutMode,
            timeoutSecs: Int = sessionTimeoutSecs,
            updateIntervalSecs: Int = lastAccessedUpdateIntervalSecs)
           (handler: Option[Handler]): Option[Handler] = {
    handler.map { _ match {
      case action: Action[_] => SessionTimeout(mode, timeoutSecs, updateIntervalSecs)(action)
      case other: Handler => other
    }}
  }
}