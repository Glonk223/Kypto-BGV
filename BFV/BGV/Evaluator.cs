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
    }
}