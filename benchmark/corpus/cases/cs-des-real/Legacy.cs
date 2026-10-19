using System.Security.Cryptography;

class Legacy {
    SymmetricAlgorithm F() { return new TripleDESCryptoServiceProvider(); }
}
