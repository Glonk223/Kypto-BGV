using System.Numerics;

namespace BGV
{
    public static class Utils
    {
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
        
        public static KeyPair SwitchKeys(KeyPair kp, BigInteger newQ)
        {
            var skNew  = ModulusSwitch(kp.SecretKey, newQ);
            var pk0New = ModulusSwitch(kp.Pk0,       newQ);
            var pk1New = ModulusSwitch(kp.Pk1,       newQ);

            var rlk0New = kp.RelinKey.Rlk0
                .Select(r => ModulusSwitch(r, newQ))
                .ToList();
            var rlk1New = kp.RelinKey.Rlk1
                .Select(r => ModulusSwitch(r, newQ))
                .ToList();
            var rlkNew  = new RelinearizationKey(rlk0New, rlk1New);

            return new KeyPair(skNew, pk0New, pk1New, kp.Error, rlkNew);
        }
    }
}