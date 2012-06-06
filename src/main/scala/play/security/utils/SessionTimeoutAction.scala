package play.security.utils

import play.mvc.Http.Context
import play.api.security.utils.SessionTimeoutConfig._
import util.control.Exception._
import play.mvc.{Result, Action}
import play.mvc.Results.AsyncResult
import util.Random

/**
 * Session timeout action
 */
class SessionTimeoutAction extends Action[SessionTimeout] {
  def call(ctx: Context) = {
    val timeoutSecs = {
      if (configuration.sessionTimeout() > 0) {
        configuration.sessionTimeout()
      } else {
        sessionTimeoutSecs
      }
    }
    val timestamp = Some(ctx.session().get(sessionTimestampKey)) flatMap { value =>
        catching(classOf[NumberFormatException]) opt (value.toLong)
    }
    val expired = timestamp map { value =>
        (System.currentTimeMillis() - timeoutSecs * 1000) > value
    } getOrElse false
    // We should block the incoming session if it is expired, or if there is a session but no timestamp is defined
    if (expired || (!ctx.session().isEmpty && !timestamp.isDefined)) {
      ctx.session().clear()
    }

    handleResult(delegate.call(ctx), timestamp, ctx)
  }

  private def handleResult(result: Result,
                           timestamp: Option[Long],
                           ctx: Context): Result = {
    result match {
      // todo handle async results properly when https://play.lighthouseapp.com/projects/82401-play-20/tickets/537-java-composition-and-asyncresults-doesnt-work is fixed
      case async: AsyncResult => async
      case plain: Result => handlePlainResult(plain, timestamp, ctx)
    }
  }

  private def handlePlainResult(result: Result,
                                timestamp: Option[Long],
                                ctx: Context): Result = {
    // If the session is empty, no need to do anything
    if (ctx.session().isEmpty) {
      return result
    }

    // If there's a new session (ie, no timestamp set in it) we need to add it.
    if (ctx.session().get(sessionTimestampKey) == null) {
      ctx.session().put(sessionTimestampKey, System.currentTimeMillis().toString)
      return result
    }

    val mode = {
      if (configuration.mode() == SessionTimeoutMode.DEFAULT) {
        sessionTimeoutMode
      } else {
        configuration.mode().scalaMode
      }
    }

    // Only need to do something now if in last accessed mode, and it's time to update the timestamp
    if (mode == play.api.security.utils.SessionTimeoutMode.LastAccessed && shouldUpdate(timestamp)) {
      ctx.session().put(sessionTimestampKey, System.currentTimeMillis().toString)
    }

    // Nothing to do
    result
  }

  private def shouldUpdate(timestamp: Option[Long]): Boolean = {
    val lastAccessedUpdateInterval = {
      if (configuration.lastAccessedUpdateInterval() > 0) {
        configuration.lastAccessedUpdateInterval()
      } else {
        lastAccessedUpdateIntervalSecs
      }
    }
    timestamp map { value =>
        (System.currentTimeMillis() - lastAccessedUpdateInterval * 1000 - Rand.rand.nextInt(10000)) > value
    } getOrElse false
  }
}

private object Rand {
  val rand = new Random
}
