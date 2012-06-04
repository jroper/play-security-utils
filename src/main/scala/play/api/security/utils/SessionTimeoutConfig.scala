package play.api.security.utils

import org.jboss.netty.handler.codec.http.DefaultCookie
import play.api.{Logger, Play}

/**
 * Configuration for the session timeout
 */
object SessionTimeoutConfig {

  /**
   * The configured session timeout mode
   */
  lazy val sessionTimeoutMode = Play.maybeApplication map {
    _.configuration.getString("session.timeout.mode")
  } map { mode =>
    SessionTimeoutMode.values.find(_.toString == mode).getOrElse(
      throw new IllegalArgumentException("Unknown session timeout mode: " + mode)
    )
  } getOrElse SessionTimeoutMode.LastAccessed

  /**
   * The configured session timeout
   */
  lazy val sessionTimeoutSecs = Play.maybeApplication flatMap {
    _.configuration.getInt("session.timeout.seconds")
  } getOrElse 7200

  /**
   * If using last accessed, how often should the cookie be updated
   */
  lazy val lastAccessedUpdateIntervalSecs = Play.maybeApplication flatMap {
    _.configuration.getInt("session.timeout.lastAccessedUpdateIntervalSeconds")
  } getOrElse 300

  /**
   * Whether Play Framework bug 511 should be worked around
   */
  lazy val workAroundCookieEncoderBug: Boolean = {
    // Detect whether the bug is present
    if (new DefaultCookie("n", "v").equals(new DefaultCookie("n", "v"))) {
      false
    } else {
      Logger.warn("Working around Play bug #511. This makes the session timeout not 100% guaranteable.")
      true
    }
  }

  val sessionTimestampKey = "_playSessionTimestamp"
}

/**
 * The mode for session timeout
 */
object SessionTimeoutMode extends Enumeration {
  type SessionTimeoutMode = Value
  /**
   * The session timeout specifies the maximum length of a session
   */
  val MaxLength = Value("maxlength")
  /**
   * The session timeout specifies the time since the session was last accessed
   */
  val LastAccessed = Value("lastaccessed")
}
