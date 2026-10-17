using System.Security.Cryptography;

class Hash {
    byte[] F(byte[] d) { using var h = SHA256.Create(); return h.ComputeHash(d); }
}
