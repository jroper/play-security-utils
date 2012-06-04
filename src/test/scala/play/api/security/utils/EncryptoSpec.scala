package play.api.security.utils

import org.specs2.mutable.Specification
import play.api.libs.Codecs

case class EncryptoSpec() extends Specification {
  "Encrypto hex decoding" should {
    "correctly parse a single hex byte" in {
      Encrypto.parseHex("3b")(0) must_== 0x3b
    }
    "correctly parse a long byte array" in {
      val str = "hello i like stuff"
      val hexBytes = Codecs.toHexString(str.getBytes)
      new String(Encrypto.parseHex(hexBytes)) must_== str
    }
  }
}
