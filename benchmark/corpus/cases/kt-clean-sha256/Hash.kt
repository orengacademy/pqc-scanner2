import java.security.MessageDigest

fun f(): ByteArray =
    MessageDigest.getInstance("SHA-256").digest("x".toByteArray())
