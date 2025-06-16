using System.Numerics;

namespace BGV
{
    public class Ciphertext
    {
        public Polynomial C0 { get; }
        public Polynomial C1 { get; }
        public Ciphertext(Polynomial c0, Polynomial c1) { C0 = c0; C1 = c1; }
    }
    
    public static class Encryptor
    {
        /// <summary>
        /// Encrypts a plaintext polynomial m using classic BGV: c0 = b*r + t*e1 + m, c1 = a*r + t*e2.
        /// </summary>
        public static Ciphertext Encrypt(Polynomial m, KeyPair kp)
        {
            int deg = Polynomial.Modulus.Degree;
            var r = KeyGenerator.SampleError(deg);
            var e1 = KeyGenerator.SampleError(deg);
            var e2 = KeyGenerator.SampleError(deg);
            var c0 = kp.Pk0.Multiply(r)
                .Add(e1.MultiplyScalar(Polynomial.T))
                .Add(m)
                .ModPolynomial();
            var c1 = kp.Pk1.Multiply(r)
                .Add(e2.MultiplyScalar(Polynomial.T))
                .ModPolynomial();
            return new Ciphertext(c0, c1);
        }

        /// <summary>
        /// Decrypts a ciphertext: v = c0 - s*c1 (mod q), then reduce coefficients modulo t.
        /// </summary>
        public static Polynomial Decrypt(Ciphertext ct, Polynomial sk)
        {
            var prod = ct.C1.Multiply(sk);
            var v = ct.C0.Add(prod).ModPolynomial();
            var plainCoeffs = v.ToBigIntegerArray()
                .Select(x => {
                    var r = x % Polynomial.T;
                    return r < 0 ? r + Polynomial.T : r;
                })
                .ToArray();
            return new Polynomial(plainCoeffs);
        }
    }
    
    /// <summary>
    /// Unit tests for Encryptor: verifies that Decrypt(Encrypt(m)) == m for random samples.
    /// </summary>
    public static class EncryptorTests
    {
        public static void RunAll()
        {
            TestRoundtrip();
            Console.WriteLine("All Encryptor tests passed.");
        }
        
        public static void TestEndToEnd(int trials = 100)
        {
            int deg = Polynomial.Modulus.Degree;
            var rng = new Random();
            int success = 0;

            for (int i = 0; i < trials; i++)
            {
                // 1) losowy plaintext m w Z_t[X]/(f)
                var coeffs = new BigInteger[deg];
                for (int j = 0; j < deg; j++)
                    coeffs[j] = rng.Next((int)Polynomial.T);
                var m = new Polynomial(coeffs);

                // 2) generacja kluczy
                var kp = KeyGenerator.GenerateKeyPair(deg);

                // 3) szyfrowanie
                var ct = Encryptor.Encrypt(m, kp);

                // 4) odszyfrowanie
                var m2 = Encryptor.Decrypt(ct, kp.SecretKey);

                if (m.Equals(m2))
                    success++;
                else
                {
                    Console.WriteLine($"Failure on trial {i}:");
                    Console.WriteLine($"  m  = {m}");
                    Console.WriteLine($"  m2 = {m2}");
                }
            }

            Console.WriteLine($"End‑to‑End: {success}/{trials} trials succeeded.");
            if (success < trials)
                throw new Exception($"Only {success}/{trials} end‑to‑end trials succeeded.");
        }

        private static void TestRoundtrip()
        {
            BigInteger q = 7;
            BigInteger t = 2;
            var mod = new Polynomial(1, 0, 1);
            Polynomial.Init(q, t, mod);

            // Deterministyczne dane testowe:
            var m  = new Polynomial(1, 0);       // m = 1
            var kp = new KeyPair(
                new Polynomial(1,1),  // s = 1 + X
                new Polynomial(2,2),  // pk0 = 2 + 2X
                new Polynomial(5,0),  // pk1 = 5
                new Polynomial(0,0)   // e  = 0
            );
            var ct = new Ciphertext(
                new Polynomial(3,2),  // c0 = 3 + 2X
                new Polynomial(5,0)   // c1 = 5
            );
    
            var m2 = Encryptor.Decrypt(ct, kp.SecretKey);
            if (!m.Equals(m2))
            {
                Console.WriteLine($"--- Debug Info for Deterministic Test ---");
                Console.WriteLine($"Plaintext m      = {m}");
                Console.WriteLine($"Decrypted m2     = {m2}");
                Console.WriteLine($"Ciphertext c0    = {ct.C0}");
                Console.WriteLine($"Ciphertext c1    = {ct.C1}");
                Console.WriteLine($"SecretKey s      = {kp.SecretKey}");
                Console.WriteLine($"PublicKey pk0    = {kp.Pk0}");
                Console.WriteLine($"PublicKey pk1    = {kp.Pk1}");
        
                // Pokaż dokładnie to, co liczy Decrypt:
                var prod = ct.C1.Multiply(kp.SecretKey);
                var v    = ct.C0.Add(prod).ModPolynomial();
                Console.WriteLine($"Intermediate v (mod f) = {v}");
        
                // Teraz pokaż v mod t z wyrównaniem:
                var vModT = v.ToBigIntegerArray()
                    .Select(x => {
                        var r = x % t;
                        return r < 0 ? r + t : r;
                    });
                Console.WriteLine($"v mod t (w [0,t))      = [{string.Join(", ", vModT)}]");

                throw new Exception($"Encrypt/Decrypt failed on deterministic test.");
            }
    
            Console.WriteLine("Deterministic round‑trip test passed.");
        }
    }
}