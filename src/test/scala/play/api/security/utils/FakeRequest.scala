package play.api.security.utils

import play.api.mvc.{AnyContent, Session, Request}


/**
 * A fake request. Needed until upgrade to Play 2.1
 */
class FakeRequest(val suppliedSession: Session = new Session) extends Request[AnyContent] {
  override lazy val session = suppliedSession
  def uri = null
  def path = null
  def method = null
  def queryString = null
  def headers = null
  def body = null
}
