using System.Numerics;
using System.Security.Cryptography;

namespace BGV
{
    /// <summary>
    /// Represents a BGV key pair containing a secret key, public key (a,b), and error polynomial.
    /// </summary>
    public class KeyPair
    {
        /// <summary>Secret key polynomial (small error).</summary>
        public Polynomial SecretKey { get; }
        /// <summary>Public key component a, sampled uniformly.</summary>
        public Polynomial PublicA { get; }
        /// <summary>Public key component b = a * sk + e.</summary>
        public Polynomial PublicB { get; }
        /// <summary>Error polynomial used in public key generation.</summary>
        public Polynomial Error { get; }

        /// <summary>
        /// Constructs a new key pair.
        /// </summary>
        /// <param name="sk">Secret key polynomial.</param>
        /// <param name="a">Uniformly sampled polynomial.</param>
        /// <param name="b">Public key polynomial b = a * sk + e.</param>
        /// <param name="e">Error polynomial.</param>
        public KeyPair(Polynomial sk, Polynomial a, Polynomial b, Polynomial e)
        {
            SecretKey = sk;
            PublicA = a;
            PublicB = b;
            Error = e;
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
            return new Polynomial(coeffs);
        }

        /// <summary>
        /// Samples a "small" error polynomial of degree ≤ <paramref name="maxDegree"/>.
        /// Coefficients are drawn from the set {-1, 0, 1}.
        /// </summary>
        /// <param name="maxDegree">
        /// Maximum degree of the error polynomial (should match modulus degree).</param>
        /// <returns>A small error polynomial.</returns>
        public static Polynomial SampleError(int maxDegree)
        {
            var coeffs = new BigInteger[maxDegree + 1];
            byte[] buf = new byte[1];
            for (int i = 0; i <= maxDegree; i++)
            {
                RandomNumberGenerator.Fill(buf);
                int r = buf[0] % 3; // yields 0,1,2
                coeffs[i] = r - 1;    // maps to -1,0,1
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
            var a = SampleUniform(modulusDegree);
            var e = SampleError(modulusDegree);
            var b = a.Multiply(sk).Add(e);
            return new KeyPair(sk, a, b, e);
        }
    }

    /// <summary>
    /// Contains unit tests for the <see cref="KeyGenerator"/>.
    /// </summary>
    public static class KeyGeneratorTests
    {
        /// <summary>
        /// Runs all tests and writes results to console.
        /// </summary>
        public static void RunAll()
        {
            TestKeyRelation();
            Console.WriteLine("All KeyGenerator tests passed.");
        }

        /// <summary>
        /// Verifies that b = a * sk + e holds exactly in the polynomial ring.
        /// </summary>
        private static void TestKeyRelation()
        {
            int degree = Polynomial.Modulus.Degree;
            var keyPair = KeyGenerator.GenerateKeyPair(degree);
            var a = keyPair.PublicA;
            var b = keyPair.PublicB;
            var sk = keyPair.SecretKey;
            var e = keyPair.Error;

            var left = a.Multiply(sk).Add(e);
            if (!left.Equals(b))
                throw new Exception("Public key relation failed: a*sk + e != b");
        }
    }
}
