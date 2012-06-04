package play.api.security.utils

import play.api.{PlayException, Play}
import java.security.MessageDigest
import javax.crypto.Cipher
import play.api.libs.Codecs
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

/**
 * Companion to the play.api.libs.Crypto class, does encryption
 */
object Encrypto {

  lazy val key = {
    Play.maybeApplication.flatMap(_.configuration.getString("application.secret")).map(secret => {
      // This is an HMAC random string, but we want a 128 bit AES key. To get that, we'll SHA-1 it, and then take
      // the first 128 bits (16 bytes)
      val digest = MessageDigest.getInstance("SHA-1")
      digest.reset()
      digest.update(secret.getBytes)
      val key = digest.digest().slice(0, 16)
      new SecretKeySpec(key, "AES")
    }).getOrElse(throw new PlayException("Configuration error", "Missing application.secret"))
  }

  /**
   * Encrypts the given String using AES with cypher block chaining. It prepends the initialisation vector to the
   * String, and separates it from the encrypted part using a pipe
   *
   * @param message The message to encrypt
   * @return The encrypted message
   */
  def encrypt(message: String): String = {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
    cipher.init(Cipher.ENCRYPT_MODE, key)
    val encrypted = Codecs.toHexString(cipher.doFinal(message.getBytes("utf-8")))
    val iv = Codecs.toHexString(cipher.getIV)
    iv + "|" + encrypted
  }

  /**
   * Decrypts the given message using AES with cypher block chaining. It expects the initialisation vector to be
   * prefixed onto the message, separated by a pipe character, in hex format. The encrypted message itself must also
   * be in hex format.
   *
   * @param message The encrypted message
   * @return The decrypted message
   */
  def decrypt(message: String): String = {
    message.split("\\|") match {
      case Array(iv, encrypted) => {
        val ivSpec = new IvParameterSpec(parseHex(iv))
        val encBytes = parseHex(encrypted)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec)
        new String(cipher.doFinal(encBytes), "utf-8")
      }
      case _ => throw new IllegalArgumentException("Message does not have iv part and encrypted part")
    }
  }

  def parseHex(message: String): Array[Byte] = {
    if (message.length % 2 != 0) {
      throw new IllegalArgumentException("Message is not a hex encoded byte array")
    }
    val result = new Array[Byte](message.length / 2)
    for (i <- 0 until (message.length) by 2) {
      result.update(i / 2, (hexDigitValue(message(i)) << 4 | hexDigitValue(message(i + 1))).asInstanceOf[Byte])
    }
    result
  }

  def hexDigitValue(digit: Char): Int = {
    digit match {
      case dec if (dec >= '0' && dec <= '9') => dec - '0'
      case dec if (dec >= 'a' && dec <= 'f') => dec - 'a' + 10
      case dec if (dec >= 'A' && dec <= 'F') => dec - 'A' + 10
      case other => throw new IllegalArgumentException("Message contains non hex character: " + other)
    }
  }

}
