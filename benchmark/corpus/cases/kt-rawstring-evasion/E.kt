import java.security.MessageDigest

fun f(b: ByteArray): String = """prefix"""" + MessageDigest.getInstance("MD5").digest(b).size
