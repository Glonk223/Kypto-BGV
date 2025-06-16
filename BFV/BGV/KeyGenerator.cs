using System.Numerics;
using System.Security.Cryptography;

namespace BGV
{
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

        public KeyPair(Polynomial sk, Polynomial pk0, Polynomial pk1, Polynomial error)
        {
            SecretKey = sk;
            Pk0 = pk0;
            Pk1 = pk1;
            Error = error;
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
            return new KeyPair(sk, pk0, pk1, e);
        }
    }

    /// <summary>
    /// Contains unit tests for the <see cref="KeyGenerator"/>.
    /// </summary>
    public static class KeyGeneratorTests
    {
        public static void RunAll()
        {
            TestKeyRelation();
            Console.WriteLine("All KeyGenerator tests passed.");
        }
        
        /// <summary>
        /// Weryfikuje, że dla wygenerowanego KeyPair zachodzi
        ///   pk0 = a * s + t * e
        /// gdzie a = -pk1 (bo pk1 = -a).
        /// </summary>
        private static void TestKeyRelation()
        {
            // musisz wywołać Init przed testem, tak jak w innych testach:
            BigInteger q = 1031;
            BigInteger t = 17;
            var mod = new Polynomial(1, 0, 0, 0, 1);  // przykładowy f(X)
            Polynomial.Init(q, t, mod);

            int deg = mod.Degree;
            for (int i = 0; i < 100; i++)
            {
                // 1) generujemy nową parę kluczy
                var kp = KeyGenerator.GenerateKeyPair(deg);

                // 2) odtwarzamy a = -pk1
                var a = kp.Pk1.Negate().ModPolynomial();

                // 3) liczymy rhs = a*s + t*e
                var rhs = a
                    .Multiply(kp.SecretKey)
                    .Add(kp.Error.MultiplyScalar(Polynomial.T))
                    .ModPolynomial();

                // 4) lhs to po prostu b = pk0
                var lhs = kp.Pk0;

                if (!lhs.Equals(rhs))
                {
                    Console.WriteLine($"--- KeyRelation failed on trial {i} ---");
                    Console.WriteLine($"a                = {a}");
                    Console.WriteLine($"s (secret key)   = {kp.SecretKey}");
                    Console.WriteLine($"e (error)        = {kp.Error}");
                    Console.WriteLine($"lhs: pk0         = {lhs}");
                    Console.WriteLine($"rhs: a*s + t*e   = {rhs}");
                    throw new Exception($"Key relation test failed on trial {i}.");
                }
            }
        }
    }
}
