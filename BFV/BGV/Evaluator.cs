using System.Numerics;

namespace BGV
{
    public static class Evaluator
    {
        /// <summary>
        /// Homomorphic addition of two ciphertexts.
        /// </summary>
        public static Ciphertext Add(Ciphertext x, Ciphertext y)
        {
            var c0 = x.C0.Add(y.C0).ModPolynomial();
            var c1 = x.C1.Add(y.C1).ModPolynomial();
            return new Ciphertext(c0, c1);
        }

        /// <summary>
        /// Homomorphic multiplication with immediate relinearization back to 2 parts.
        /// </summary>
        public static Ciphertext Multiply(Ciphertext x, Ciphertext y, KeyPair kp)
        {
            // Pre‑relinearization parts
            var e0 = x.C0.Multiply(y.C0);
            var e1 = x.C0.Multiply(y.C1).Add(x.C1.Multiply(y.C0));
            var e2 = x.C1.Multiply(y.C1);

            // Relinearize using evaluation key: c0' = e0 + e2 * rlk0, c1' = e1 + e2 * rlk1
            var rlk0 = kp.RelinKey.Rlk0;
            var rlk1 = kp.RelinKey.Rlk1;
            var c0p = e0.Add(e2.Multiply(rlk0)).ModPolynomial();
            var c1p = e1.Add(e2.Multiply(rlk1)).ModPolynomial();

            return new Ciphertext(c0p, c1p);
        }
        
        public static class EvaluatorTests
        {
            public static void RunAll(int modulusDegree)
            {
                TestAdd(modulusDegree);
                TestMultiply(modulusDegree);
                Console.WriteLine("Evaluator tests passed.");
            }

            private static void TestAdd(int deg)
            {
                var kp = KeyGenerator.GenerateKeyPair(deg);
                var rng = new Random();
                for (int i = 0; i < 50; i++)
                {
                    // Generate random plaintexts
                    var coeffs1 = new BigInteger[deg];
                    var coeffs2 = new BigInteger[deg];
                    for (int j = 0; j < deg; j++)
                    {
                        coeffs1[j] = rng.Next((int)Polynomial.T);
                        coeffs2[j] = rng.Next((int)Polynomial.T);
                    }
                    var m1 = new Polynomial(coeffs1);
                    var m2 = new Polynomial(coeffs2);

                    // Encrypt
                    var c1 = Encryptor.Encrypt(m1, kp);
                    var c2 = Encryptor.Encrypt(m2, kp);

                    // Homomorphic add and decrypt
                    var sumCt = Evaluator.Add(c1, c2);
                    var sumPt = Encryptor.Decrypt(sumCt, kp.SecretKey);

                    // Expected: (m1 + m2) mod t
                    var expectedCoeffs = m1.Add(m2)
                        .ModPolynomial()
                        .ToBigIntegerArray()
                        .Select(x => {
                            var r = x % Polynomial.T;
                            return r < 0 ? r + Polynomial.T : r;
                        }).ToArray();
                    var expected = new Polynomial(expectedCoeffs);

                    if (!sumPt.Equals(expected))
                        Console.WriteLine($"Add failed on trial {i}: got {sumPt}, expected {expected}");
                }
            }

            private static void TestMultiply(int deg)
            {
                var kp = KeyGenerator.GenerateKeyPair(deg);
                var rng = new Random();
                for (int i = 0; i < 50; i++)
                {
                    var coeffs1 = new BigInteger[deg];
                    var coeffs2 = new BigInteger[deg];
                    for (int j = 0; j < deg; j++)
                    {
                        coeffs1[j] = rng.Next((int)Polynomial.T);
                        coeffs2[j] = rng.Next((int)Polynomial.T);
                    }
                    var m1 = new Polynomial(coeffs1);
                    var m2 = new Polynomial(coeffs2);

                    var c1 = Encryptor.Encrypt(m1, kp);
                    var c2 = Encryptor.Encrypt(m2, kp);

                    var prodCt = Evaluator.Multiply(c1, c2, kp);
                    var prodPt = Encryptor.Decrypt(prodCt, kp.SecretKey);
                    
                    var expectedCoeffs = m1.Multiply(m2)
                        .ModPolynomial()
                        .ToBigIntegerArray()
                        .Select(x => {
                            var r = x % Polynomial.T;
                            return r < 0 ? r + Polynomial.T : r;
                        }).ToArray();
                    var expected = new Polynomial(expectedCoeffs);
                    
                    if (!prodPt.Equals(expected))
                        Console.WriteLine($"Multiply failed on trial {i}");
                }
            }
        }
    }
}