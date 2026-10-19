import java.security.MessageDigest

fun f(): ByteArray =
    MessageDigest.getInstance("MD5").digest("x".toByteArray())
