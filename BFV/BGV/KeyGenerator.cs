using System.Numerics;
using System.Security.Cryptography;

namespace BGV
{
    /// <summary>
    /// Holds the relinearization key encrypting s^2 under secret s.
    /// Represents a ciphertext (rlk0, rlk1) such that rlk0 + rlk1 * s = s^2 (mod q, f).
    /// </summary>
    public class RelinearizationKey
    {
        public Polynomial Rlk0 { get; }
        public Polynomial Rlk1 { get; }
        public RelinearizationKey(Polynomial rlk0, Polynomial rlk1)
        {
            Rlk0 = rlk0;
            Rlk1 = rlk1;
        }
    }
    
    /// <summary>
    /// Represents a BGV key pair containing a secret key, public key (a,b), and error polynomial.
    /// </summary>
    /// <summary>Key pair with public key expressed as (pk0, pk1=-a).</summary>
    public class KeyPair
    {
        public Polynomial SecretKey { get; }
        public Polynomial Pk0 { get; }  // = a*s + t*e
        public Polynomial Pk1 { get; }  // = -a
        public Polynomial Error { get; }
        
        public RelinearizationKey RelinKey { get; }
        
        public KeyPair(Polynomial sk, Polynomial pk0, Polynomial pk1, Polynomial error, RelinearizationKey rlk)
        {
            SecretKey = sk;
            Pk0 = pk0;
            Pk1 = pk1;
            Error = error;
            RelinKey = rlk;
        }
    }

    /// <summary>
    /// Provides methods for generating BGV keys and sampling polynomials.
    /// </summary>
    public static class KeyGenerator
    {
        /// <summary>
        /// Samples a polynomial of degree ≤ <paramref name="maxDegree"/> with coefficients
        /// uniformly random in [0, Q).
        /// </summary>
        /// <param name="maxDegree">
        /// Maximum degree of the sampled polynomial (should match modulus degree).</param>
        /// <returns>A uniformly random polynomial in Z_q[X]/(f).</returns>
        public static Polynomial SampleUniform(int maxDegree)
        {
            var coeffs = new BigInteger[maxDegree + 1];
            byte[] buf = new byte[8];
            for (int i = 0; i <= maxDegree; i++)
            {
                RandomNumberGenerator.Fill(buf);
                var val = new BigInteger(buf);
                coeffs[i] = (val < 0 ? -val : val) % Polynomial.Q;
            }
            return new Polynomial(coeffs).ModPolynomial();
        }

        /// <summary>
        /// Samples a "small" error polynomial of degree ≤ <paramref name="degree"/>.
        /// Coefficients are drawn from the set {-1, 0, 1}.
        /// </summary>
        /// <param name="degree">
        /// Maximum degree of the error polynomial (should match modulus degree).</param>
        /// <returns>A small error polynomial.</returns>
        public static Polynomial SampleError(int degree, 
            double pNeg = 0.001, double pZero = 0.998, double pPos = 0.001)
        {
            if (Math.Abs(pNeg + pZero + pPos - 1.0) > 1e-9)
                throw new ArgumentException("pNeg + pZero + pPos must sum to 1");

            var coeffs = new BigInteger[degree + 1];
            byte[] buf = new byte[8];
            for (int i = 0; i <= degree; i++)
            {
                // 1) wylosuj double u w [0,1)
                RandomNumberGenerator.Fill(buf);
                // zamien bajty na UInt64, podziel przez 2^64 → [0,1)
                var u = (BitConverter.ToUInt64(buf, 0) / (double)ulong.MaxValue);

                // 2) przypisz wartość wg wagi
                if (u < pNeg)
                    coeffs[i] = -1;
                else if (u < pNeg + pZero)
                    coeffs[i] = 0;
                else
                    coeffs[i] = 1;
            }
            return new Polynomial(coeffs);
        }
        /// <summary>
        /// Generates a BGV key pair: secret key, public key, and error.
        /// </summary>
        /// <param name="modulusDegree">
        /// Degree of the ring modulus polynomial f(X).</param>
        /// <returns>A new <see cref="KeyPair"/> instance.</returns>
        public static KeyPair GenerateKeyPair(int modulusDegree)
        {
            var sk = SampleError(modulusDegree);
            var a  = SampleUniform(modulusDegree);
            var e  = SampleError(modulusDegree);
            var scaledError = e.MultiplyScalar(Polynomial.T);
            var pk0 = a.Multiply(sk).Add(scaledError).ModPolynomial();  // a*s + t*e
            var pk1 = a.Negate().ModPolynomial();                       // -a
            
            // Build relinearization key for s^2
            // Compute s^2
            var s2 = sk.Multiply(sk).ModPolynomial();
            // Sample fresh randomness for relin key
            var a2 = SampleUniform(modulusDegree);
            var e2 = SampleError(modulusDegree);
            // rlk0 = a2*s + t*e2 + s2
            var rlk0 = a2.Multiply(sk)
                .Add(e2.MultiplyScalar(Polynomial.T))
                .Add(s2)
                .ModPolynomial();
            // rlk1 = -a2
            var rlk1 = a2.Negate().ModPolynomial();
            var rlk = new RelinearizationKey(rlk0, rlk1);
            
            return new KeyPair(sk, pk0, pk1, e, rlk);
        }
    }
}
