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

            // Decompose e2 into gadget digits
            var e2_decomp = Utils.Decompose(e2, KeyGenerator.GadgetBase, KeyGenerator.GadgetLength);

            // Start relinearized sums
            var c0p = e0;
            var c1p = e1;
            for (int j = 0; j < e2_decomp.Count; j++)
            {
                c0p = c0p.Add(kp.RelinKey.Rlk0[j].Multiply(e2_decomp[j]));
                c1p = c1p.Add(kp.RelinKey.Rlk1[j].Multiply(e2_decomp[j]));
            }

            return new Ciphertext(c0p.ModPolynomial(), c1p.ModPolynomial());
        }
        
        /// <summary>
        /// Modulus switching of a ciphertext from current Q to newQ.
        /// </summary>
        public static Ciphertext ModulusSwitch(Ciphertext ct, BigInteger newQ)
        {
            var c0_new = Utils.ModulusSwitch(ct.C0, newQ);
            var c1_new = Utils.ModulusSwitch(ct.C1, newQ);
            return new Ciphertext(c0_new, c1_new);
        }
    }
}