import java.security.KeyPairGenerator

fun f() {
    val g = KeyPairGenerator.getInstance("RSA")
    g.initialize(2048)
}
