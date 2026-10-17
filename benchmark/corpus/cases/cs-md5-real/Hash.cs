using System.Security.Cryptography;

class Hash {
    byte[] F(byte[] d) { using var h = MD5.Create(); return h.ComputeHash(d); }
}
