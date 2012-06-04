package play.api.security.utils

import SessionTimeoutConfig._
import SessionTimeoutMode._
import util.control.Exception._
import util.Random
import play.api.mvc._
import play.api.http.HeaderNames

/**
 * Provides a session timeout.
 */
case class SessionTimeoutAction[A](mode: SessionTimeoutMode = sessionTimeoutMode,
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
    val blockSession = expired || (!request.session.isEmpty && !timestamp.isDefined && !workAroundCookieEncoderBug)

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
      return result.discardingCookies(Session.COOKIE_NAME)
    }

    // If there's a new session (ie, no timestamp set in it) we need to add it.
    if (!session.isEmpty && session.get(sessionTimestampKey).isEmpty) {
      return result.withSession(session + (sessionTimestampKey -> System.currentTimeMillis().toString))
    }

    // Work around for bug #511
    if (workAroundCookieEncoderBug && !incomingSession.isEmpty && session.isEmpty && timestamp.isEmpty) {
      return (result.withSession(incomingSession + (sessionTimestampKey -> System.currentTimeMillis().toString)))
    }

    // Only need to do something now if in last accessed mode, and it's time to update the timestamp
    if (mode == LastAccessed && shouldUpdate(timestamp)) {
      // If there's a session set in the result, update the timestamp in that
      if (!session.isEmpty) {
        return result.withSession(session + (sessionTimestampKey -> System.currentTimeMillis().toString))
      }
      // Otherwise, set the timestamp from the incoming session
      return (result.withSession(incomingSession + (sessionTimestampKey -> System.currentTimeMillis().toString)))
    }

    // Nothing to do
    result
  }

  private def shouldUpdate(timestamp: Option[Long]): Boolean = {
    timestamp map { value =>
      mode == LastAccessed  &&
        (System.currentTimeMillis() - lastAccessedUpdateIntervalSecs * 1000 - rand.nextInt(10000)) > value
    } getOrElse false
  }

  lazy val parser = action.parser
}
