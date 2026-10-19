using System.Security.Cryptography;

class Keys {
    RSA F() { return RSA.Create(2048); }
}
