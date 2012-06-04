package play.api.security.utils

import play.api.mvc.Session
import play.api.libs.Crypto

/**
 * Provides secure session features
 */
case class SecureSession(session: Session) {

  /**
   * Put the given value into the session, with the given token, hashing it if required.  This is intended to be
   * retrieved and validated in two steps, first by a call to get() to retrieve the value, then once the token for
   * that value has been looked up, it can be verified by calling verifyValueWithToken().
   *
   * @param key The session key
   * @param value The value to put in the session
   * @param token The token to associate with the value
   * @param hashToken Whether the token should be hashed
   * @return The updated session
   */
  def putWithToken(key: String, value: String, token: String, hashToken: Boolean = true): Session =
    session + (key -> value) + (key + SecureSession.TOKEN_SUFFIX -> hash(value, token, hashToken))

  /**
   * Get the value verified by the token that is returned by the given value to token function.
   *
   * @param key The key for the value in the session
   * @param hashToken Whether the token should be hashed
   * @param tokenFunction A function that converts a value to a token.  If this returns None, then this function will
   *                      also return None.
   * @return Some value, verified to match the token, or None if it's not found, or if the token is not found or
   *         doesn't verify
   */
  def getVerifiedByToken(key: String, hashToken: Boolean = true)(tokenFunction: String => Option[String]): Option[String] = {
    // Get the value and token from the session
    session.get(key) flatMap { value =>
      session.get(key + SecureSession.TOKEN_SUFFIX) map { sessionToken =>
        (value -> sessionToken)
      }
    } flatMap { pair =>
      val (value, sessionToken) = pair
      // Look up the token for the value, and filter it to match only if our hash matches the session token
      tokenFunction(value) filter { ourToken =>
        hash(value, ourToken, hashToken) == sessionToken
      } map { token =>
        // If we still have a value at this point, then it gets mapped to the value
        value
      }
    }
  }

  /**
   * Remove a value that has been stored with a token
   *
   * @param key The key for the value
   * @return The modified session
   */
  def removeWithToken(key: String): Session =
    session - key - (key + SecureSession.TOKEN_SUFFIX)

  /**
   * Put a sensitive value into the session. This will encrypt the value first
   *
   * @param key The key for the value
   * @param value The value
   * @return The modified session
   */
  def putSensitive(key: String, value: String): Session = session + (key -> Encrypto.encrypt(value))

  /**
   * Get a sensitive value from the session. This will decrypt the value.
   *
   * @param key The key for the value
   * @return Some decrypted value, or None
   */
  def getSensitive(key: String): Option[String] = session.get(key).map(value => Encrypto.decrypt(value))

  private def hash(value: String, token: String, hashToken: Boolean): String = {
    if (hashToken) {
      Crypto.sign(value + token)
    } else {
      token
    }
  }
}

object SecureSession {
  val TOKEN_SUFFIX = "._token_"

  implicit def convertSecureSession(session: Session): SecureSession = new SecureSession(session)
}
