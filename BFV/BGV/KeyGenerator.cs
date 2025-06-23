using System.Numerics;
using System.Security.Cryptography;

namespace BGV
{
    public class RelinearizationKey
    {
        public IReadOnlyList<Polynomial> Rlk0 { get; }
        public IReadOnlyList<Polynomial> Rlk1 { get; }

        public RelinearizationKey(List<Polynomial> rlk0, List<Polynomial> rlk1)
        {
            if (rlk0.Count != rlk1.Count)
                throw new ArgumentException("Mismatched RelinearizationKey lengths");
            Rlk0 = rlk0;
            Rlk1 = rlk1;
        }
    }
    
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


    public static class KeyGenerator
    {
        public static BigInteger GadgetBase = 1 << 20;
        public static int GadgetLength =>
            (int)Math.Ceiling(Math.Log((double)Polynomial.Q, (double)GadgetBase));
        
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
        
        public static Polynomial SampleError(int degree, 
            double pNeg = 0.075, double pZero = 0.85, double pPos = 0.075)
        {
            if (Math.Abs(pNeg + pZero + pPos - 1.0) > 1e-9)
                throw new ArgumentException("pNeg + pZero + pPos must sum to 1");

            var coeffs = new BigInteger[degree + 1];
            byte[] buf = new byte[8];
            for (int i = 0; i <= degree; i++)
            {
                RandomNumberGenerator.Fill(buf);
                var u = (BitConverter.ToUInt64(buf, 0) / (double)ulong.MaxValue);

                if (u < pNeg)
                    coeffs[i] = -1;
                else if (u < pNeg + pZero)
                    coeffs[i] = 0;
                else
                    coeffs[i] = 1;
            }
            return new Polynomial(coeffs);
        }
        public static KeyPair GenerateKeyPair(int modulusDegree)
        {
            var sk = SampleError(modulusDegree);
            var a  = SampleUniform(modulusDegree);
            var e  = SampleError(modulusDegree);
            var scaledError = e.MultiplyScalar(Polynomial.T);
            var pk0 = a.Multiply(sk).Add(scaledError).ModPolynomial();
            var pk1 = a.Negate().ModPolynomial();
            
            var s2 = sk.Multiply(sk).ModPolynomial();
            var s2_decomp = Utils.Decompose(s2, GadgetBase, GadgetLength);

            var rlk0 = new List<Polynomial>();
            var rlk1 = new List<Polynomial>();
            foreach (var s2j in s2_decomp)
            {
                var a_j = SampleUniform(modulusDegree);
                var e_j = SampleError(modulusDegree);
                var r0 = a_j.Multiply(sk)
                    .Add(e_j.MultiplyScalar(Polynomial.T))
                    .Add(s2j)
                    .ModPolynomial();
                var r1 = a_j.Negate().ModPolynomial();
                rlk0.Add(r0);
                rlk1.Add(r1);
            }
            var rlk = new RelinearizationKey(rlk0, rlk1);
            return new KeyPair(sk, pk0, pk1, e, rlk);
        }
    }
}
