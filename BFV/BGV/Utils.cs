using System.Numerics;

namespace BGV
{
    /// <summary>
    /// Implements gadget decomposition and modulus switching utilities for BGV.
    /// </summary>
    public static class Utils
    {
        /// <summary>
        /// Decomposes polynomial p in base B into l digits (lowest first).
        /// </summary>
        public static List<Polynomial> Decompose(Polynomial p, BigInteger B, int l)
        {
            var coeffs = p.ToBigIntegerArray();
            var digits = new List<BigInteger[]>();
            for (int j = 0; j < l; j++)
                digits.Add(new BigInteger[coeffs.Length]);
            
            for (int i = 0; i < coeffs.Length; i++)
            {
                var x = coeffs[i];
                for (int j = 0; j < l; j++)
                {
                    digits[j][i] = x % B;
                    x /= B;
                }
            }

            return digits.Select(arr => new Polynomial(arr)).ToList();
        }

        /// <summary>
        /// Switches a polynomial from modulus Q_old to Q_new: round(c * Q_new / Q_old) mod Q_new
        /// </summary>
        public static Polynomial ModulusSwitch(Polynomial p, BigInteger Q_new)
        {
            var Q_old = Polynomial.Q;
            var oldCoeffs = p.ToBigIntegerArray();
            var newCoeffs = new BigInteger[oldCoeffs.Length];
            for (int i = 0; i < oldCoeffs.Length; i++)
            {
                var c = oldCoeffs[i];
                var num = c * Q_new + Q_old / 2;
                var y = num / Q_old;
                newCoeffs[i] = ((y % Q_new) + Q_new) % Q_new;
            }
            return new Polynomial(newCoeffs);
        }
        
        /// <summary>
        /// Przełącza wszystkie wielomiany w KeyPair do nowego modułu newQ.
        /// </summary>
        public static KeyPair SwitchKeys(KeyPair kp, BigInteger newQ)
        {
            // 1) Przełącz secret key i public key
            var skNew  = ModulusSwitch(kp.SecretKey, newQ);
            var pk0New = ModulusSwitch(kp.Pk0,       newQ);
            var pk1New = ModulusSwitch(kp.Pk1,       newQ);

            // 2) Przełącz relinearization key (lista par)
            var rlk0New = kp.RelinKey.Rlk0
                .Select(r => ModulusSwitch(r, newQ))
                .ToList();
            var rlk1New = kp.RelinKey.Rlk1
                .Select(r => ModulusSwitch(r, newQ))
                .ToList();
            var rlkNew  = new RelinearizationKey(rlk0New, rlk1New);

            // (opcjonalnie) błąd
            // var errNew = Utils.ModulusSwitch(kp.Error, newQ);

            return new KeyPair(skNew, pk0New, pk1New, kp.Error, rlkNew);
        }
    }
}