    // Operator %: redukcja współczynników wielomianu do dowolnego mod
    
using System;
using System.Linq;


public class Rq
{
    public static int N = 4; // stopień wielomianu
    public static int q = 17;
    public static int[] modulusPoly = null; // X^N + 1
    public int[] Coeffs;

    // Ustawia nową wartość N i resetuje modulusPoly
    public static void SetN(int newN)
    {
        N = newN;
        modulusPoly = null;
    }

    public Rq(int[] coeffs)
    {
        // Inicjalizacja modulusPoly jeśli nie została ustawiona lub niezgodna z N
        if (modulusPoly == null || modulusPoly.Length != N + 1)
        {
            modulusPoly = new int[N + 1];
            modulusPoly[0] = 1;
            modulusPoly[N] = 1;
            for (int i = 1; i < N; i++) modulusPoly[i] = 0;
        }
        this.Coeffs = ReducePoly(coeffs);
    }


    public override string ToString()
    {
        return "[" + string.Join(", ", Coeffs) + "]";
    }

    private int[] ReducePoly(int[] poly)
    {
        // Zredukuj wielomian modulo X^N + 1
        int n = N;
        int[] result = new int[n];

        for (int i = 0; i < poly.Length; i++)
        {
            int coeff = poly[i] % q;
            if (coeff < 0) coeff += q;

            if (i < n)
            {
                result[i] = (result[i] + coeff) % q;
            }
            else
            {
                // X^k = -X^{k-n} mod X^n + 1
                int deg = i % n;
                result[deg] = (result[deg] - coeff + q) % q;
            }
        }

        return result;
    }

    public static Rq operator +(Rq a, Rq b)
    {
        return new Rq(a.Coeffs.Zip(b.Coeffs, (x, y) => (x + y) % q).ToArray());
    }

    public static Rq operator -(Rq a, Rq b)
    {
        return new Rq(a.Coeffs.Zip(b.Coeffs, (x, y) => (x - y + q) % q).ToArray());
    }

    public static Rq operator *(Rq a, Rq b)
    {
        int deg = a.Coeffs.Length + b.Coeffs.Length - 1;
        int[] result = new int[deg];

        for (int i = 0; i < a.Coeffs.Length; i++)
        {
            for (int j = 0; j < b.Coeffs.Length; j++)
            {
                result[i + j] += a.Coeffs[i] * b.Coeffs[j];
            }
        }

        return new Rq(result);
    }

    public static Rq operator *(int scalar, Rq a)
    {
        return new Rq(a.Coeffs.Select(x => (scalar * x) % q).ToArray());
    }

    // Operator %: redukcja współczynników wielomianu do dowolnego mod
    public static Rq operator %(Rq a, int mod)
    {
        return new Rq(a.Coeffs.Select(x => ((x % mod) + mod) % mod).ToArray());
    }
    
    public static Rq operator -(Rq a)
    {
        return new Rq(a.Coeffs.Select(x => (-x + q) % q).ToArray());
    }
}
