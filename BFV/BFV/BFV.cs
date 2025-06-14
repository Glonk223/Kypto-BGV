using System;
using System.Linq;


public class BFV
{
    public static int t = 17;   // Modulo plaintextu
    public static int q = Rq.q; // Modulo ciphertextu

    public Rq sk;   // Secret key
    public (Rq, Rq) pk; // Public key (pk0, pk1)
    public (Rq, Rq) rlk; // Relinearization key (rlk0, rlk1)

    // Noise budget: max log2(q/t) - log2(noise)
    public int maxNoiseBudget = (int)Math.Floor(Math.Log(q / (double)t, 2));

    Random rand = new Random();

    public BFV()
    {
        KeyGen();
    }

    private int[] SampleTernary(int n)
    {
        return Enumerable.Range(0, n).Select(_ => rand.Next(3) - 1).ToArray(); // -1, 0, 1
    }


    private Rq SampleError()
    {
        return new Rq(SampleTernary(Rq.N));
    }


    private Rq RandomPoly()
    {
        int[] coeffs = Enumerable.Range(0, Rq.N).Select(_ => rand.Next(q)).ToArray();
        return new Rq(coeffs);
    }

    public void KeyGen()
    {
        sk = new Rq(SampleTernary(Rq.N)); // Sekretny klucz
        var a = RandomPoly();
        var e = SampleError();

        var pk0 = a * sk + t * e;
        var pk1 = -a;
        pk = (pk0, pk1);

        // Relinearization key generation
        // rlk0 = a_rlk * sk + t * e_rlk + sk*sk
        // rlk1 = -a_rlk
        var a_rlk = RandomPoly();
        var e_rlk = SampleError();
        var rlk0 = a_rlk * sk + t * e_rlk + sk * sk;
        var rlk1 = -a_rlk;
        rlk = (rlk0, rlk1);
    }

    // Ciphertext: (Rq, Rq, int noise)
    public (Rq, Rq, int) Encrypt(Rq m)
    {
        var (pk0, pk1) = pk;

        // Skalowanie wiadomości przez Δ = floor(q / t)
        int delta = q / t;
        Rq mScaled = new Rq(m.Coeffs.Select(x => (x * delta) % q).ToArray());

        Rq u = SampleError(); // lub ternary
        Rq e1 = SampleError();
        Rq e2 = SampleError();

        Rq c0 = pk0 * u + t * e1 + mScaled;
        Rq c1 = pk1 * u + t * e2;

        // Szacowanie szumu: noise = ||t*e1 + mScaled||
        int noise = MaxAbsCoeff(t * e1 + mScaled);
        return (c0, c1, noise);
    }

    public Rq Decrypt((Rq, Rq, int) ct)
    {
        var (c0, c1, _) = ct;
        Rq result = c0 + (c1 * sk);
        // Odskałowanie przez delta i zaokrąglenie
        int delta = q / t;
        int[] coeffs = result.Coeffs.Select(x => {
            int v = ((x % q) + q) % q;
            int rounded = (int)Math.Round(v / (double)delta);
            return ((rounded % t) + t) % t;
        }).ToArray();
        return new Rq(coeffs);
    }

    public (Rq, Rq, int) Add((Rq, Rq, int) ct1, (Rq, Rq, int) ct2)
    {
        // Dodajemy ciphertexty i sumujemy szumy
        var c0 = ct1.Item1 + ct2.Item1;
        var c1 = ct1.Item2 + ct2.Item2;
        int noise = ct1.Item3 + ct2.Item3;
        return (c0, c1, noise);
    }

    public (Rq, Rq, int) Mul((Rq, Rq, int) ct1, (Rq, Rq, int) ct2)
    {
        // Mnożenie ciphertextów: (c0a, c1a) * (c0b, c1b) = (c0, c1, c2)
        var (c0a, c1a, noise1) = ct1;
        var (c0b, c1b, noise2) = ct2;

        Rq c0 = c0a * c0b;
        Rq c1 = c0a * c1b + c1a * c0b;
        Rq c2 = c1a * c1b;

        // Relinearyzacja: (c0, c1, c2) -> (c0', c1')
        var (rlk0, rlk1) = rlk;
        Rq c0p = c0 + rlk0 * c2;
        Rq c1p = c1 + rlk1 * c2;

        // Szacowanie szumu po mnożeniu: noise rośnie ~ noise1*noise2
        int noise = noise1 * noise2;
        return (c0p, c1p, noise);
    }

    // Modulus switching: zmniejsz q i szum
    public (Rq, Rq, int) ModSwitch((Rq, Rq, int) ct, int newQ)
    {
        // Redukcja współczynników ciphertextu do nowego q
        var c0 = ct.Item1 % newQ;
        var c1 = ct.Item2 % newQ;
        // Szum maleje proporcjonalnie do nowego q
        int noise = (int)Math.Floor(ct.Item3 * (newQ / (double)q));
        return (c0, c1, noise);
    }

    // Odczytaj noise budget (ile bitów szumu pozostało)
    public int GetNoiseBudget((Rq, Rq, int) ct)
    {
        if (ct.Item3 == 0) return maxNoiseBudget;
        return maxNoiseBudget - (int)Math.Ceiling(Math.Log(ct.Item3, 2));
    }

    // Pomocnicza: max wartość bezwzględna współczynnika
    private int MaxAbsCoeff(Rq poly)
    {
        return poly.Coeffs.Select(Math.Abs).Max();
    }
}
