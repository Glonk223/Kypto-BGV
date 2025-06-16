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
}