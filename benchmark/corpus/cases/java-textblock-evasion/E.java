import java.security.MessageDigest;

class E {
    String a = """
        escaped \""" still inside
        """;
    void f() throws Exception { MessageDigest.getInstance("MD5"); }
    String b = """
        tail
        """;
}
