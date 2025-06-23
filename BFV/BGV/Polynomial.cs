using System.Numerics;
using System.Security.Cryptography;

namespace BGV
{
    /// <summary>
    /// Represents a polynomial over Z_q and provides operations in the quotient ring Z_q[X] / (modulus)
    /// </summary>
    public class Polynomial
    {
        private readonly List<BigInteger> _coeffs;
        public static BigInteger Q { get; private set; }
        public static BigInteger T { get; private set; }
        public static Polynomial Modulus { get; private set; }

        /// <summary>
        /// Set global ring parameters: modulus polynomial and coefficient modulus q.
        /// Must be called before any operations.
        /// </summary>
        public static void Init(BigInteger q, BigInteger t,  Polynomial modulus)
        {
            if (q <= 1) throw new ArgumentException("q must be prime > 1");
            if (t <= 1 || t >= q) throw new ArgumentException("t must satisfy 1 < t < q");

            Q = q;
            T = t;
            Modulus = modulus;
        }

        /// <summary>
        /// Constructs a polynomial from integer coefficients (lowest degree first).
        /// </summary>
        public Polynomial(params BigInteger[] input)
        {
            _coeffs = new List<BigInteger>(input);
            Normalize();
        }

        private Polynomial(List<BigInteger> c)
        {
            _coeffs = c;
            Normalize();
        }
        
        /// <summary>
        /// Degree of the polynomial
        /// </summary>
        public int Degree => _coeffs.Count - 1;

        /// <summary>
        /// Adds two polynomials in the ring
        /// </summary>
        public Polynomial Add(Polynomial other)
        {
            int maxD = Math.Max(Degree, other.Degree);
            var result = new List<BigInteger>(new BigInteger[maxD + 1]);
            for (int i = 0; i <= maxD; i++)
            {
                BigInteger a = i <= Degree ? _coeffs[i] : 0;
                BigInteger b = i <= other.Degree ? other._coeffs[i] : 0;
                result[i] = SafeModQ(a + b);
            }
            return new Polynomial(result).ModPolynomial();
        }

        /// <summary>
        /// Multiplies two polynomials in the ring
        /// </summary>
        public Polynomial Multiply(Polynomial other)
        {
            int degA = Degree, degB = other.Degree;
            var result = new List<BigInteger>(new BigInteger[degA + degB + 1]);
            for (int i = 0; i <= degA; i++)
                for (int j = 0; j <= degB; j++)
                    result[i + j] += _coeffs[i] * other._coeffs[j];

            for (int k = 0; k < result.Count; k++)
                result[k] = SafeModQ(result[k]);

            return new Polynomial(result).ModPolynomial();
        }
        
        /// <summary>
        /// Multiply each coefficient by a scalar (e.g. plaintext modulus T).
        /// </summary>
        public Polynomial MultiplyScalar(BigInteger scalar)
        {
            var result = _coeffs.Select(c => SafeModQ(c * scalar)).ToArray();
            return new Polynomial(result);
        }
        
        /// <summary>
        /// Negates polynomial: -this mod q.
        /// </summary>
        public Polynomial Negate() => MultiplyScalar(-1);
        
        /// <summary>
        /// Reduces this polynomial modulo the Modulus polynomial
        /// </summary>
        public Polynomial ModPolynomial()
        {
            if (Modulus == null)
                return this;

            var res = new List<BigInteger>(_coeffs);
            int modDeg = Modulus.Degree;
            while (res.Count - 1 >= modDeg)
            {
                int curDeg = res.Count - 1;
                BigInteger factor = res[curDeg];
                if (factor != 0)
                {
                    for (int i = 0; i <= modDeg; i++)
                    {
                        int idx = curDeg - modDeg + i;
                        res[idx] = SafeModQ(res[idx] - factor * Modulus._coeffs[i]);
                    }
                }
                res.RemoveAt(curDeg);
            }
            return new Polynomial(res);
        }

        /// <summary>
        /// Ensures all coefficients are in [0, Q)
        /// and trims leading zeros
        /// </summary>
        public void Normalize()
        {
            for (int i = 0; i < _coeffs.Count; i++)
                _coeffs[i] = SafeModQ(_coeffs[i]);
            // trim
            for (int i = _coeffs.Count - 1; i > 0; i--)
            {
                if (_coeffs[i] == 0)
                    _coeffs.RemoveAt(i);
                else break;
            }
        }

        public static BigInteger SafeModQ(BigInteger x)
        {
            if (Q == 0) return x;  // Q not initialized yet
            x %= Q;
            return x < 0 ? x + Q : x;
        }
        
        /// <summary>
        /// Returns the internal coefficients array (lowest degree first).
        /// </summary>
        public BigInteger[] ToBigIntegerArray() => _coeffs.ToArray();

        public override bool Equals(object? obj)
        {
            if (obj is not Polynomial p) return false;
            var a = _coeffs;
            var b = p._coeffs;
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        public override int GetHashCode() => _coeffs.Aggregate(0, (h, c) => HashCode.Combine(h, c));

        public override string ToString()
        {
            if (Degree < 0) return "0";
            var parts = new List<string>();
            for (int i = 0; i < _coeffs.Count; i++)
            {
                var c = _coeffs[i];
                if (c == 0) continue;
                var term = c == 1 && i > 0 ? "" : c.ToString();
                if (i == 1) term += "X";
                else if (i > 1) term += $"X^{i}";
                parts.Add(term);
            }
            return parts.Count > 0 ? string.Join(" + ", parts) : "0";
        }
    }
}
