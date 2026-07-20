import javax.crypto.Cipher;

class B {
  void f() throws Exception {
    Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
  }
}
