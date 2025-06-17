using System.Diagnostics;
using System.Numerics;


namespace BGV
{
    public class BenchmarkResult
    {
        public int ModulusDegree { get; set; }
        public BigInteger Q { get; set; }
        public BigInteger T { get; set; }
        public TimeSpan KeyGenTime { get; set; }
        public TimeSpan EncryptTime { get; set; }
        public TimeSpan DecryptTime { get; set; }
        public TimeSpan AddTime { get; set; }
        public TimeSpan MultiplyTime { get; set; }

        public override string ToString()
        {
            return
                $"N={ModulusDegree}, q={Q}, t={T}\n" +
                $"  KeyGen:     {KeyGenTime.TotalMilliseconds / 1000.0:F4} s\n" +
                $"  Encrypt:    {EncryptTime.TotalMilliseconds / 1000.0:F4} s\n" +
                $"  Decrypt:    {DecryptTime.TotalMilliseconds / 1000.0:F4} s\n" +
                $"  Add:        {AddTime.TotalMilliseconds / 1000.0:F4} s\n" +
                $"  Multiply:   {MultiplyTime.TotalMilliseconds / 1000.0:F4} s\n";
        }
    }

    public static class Benchmark
    {
        /// <summary>
        /// Przeprowadza benchmark BGV przy zadanych parametrach i zwraca wyniki.
        /// </summary>
        /// <param name="modulusDegree">Stopień wielomianu pierścienia</param>
        /// <param name="q">Moduł q</param>
        /// <param name="t">Moduł t</param>
        /// <param name="modulusPoly">Wielomian nieskracalny (f(X))</param>
        /// <param name="iterations">Liczba iteracji dla każdej operacji</param>
        public static BenchmarkResult Run(
            int modulusDegree,
            BigInteger q,
            BigInteger t,
            Polynomial modulusPoly,
            int iterations = 10)
        {
            // Zainicjalizuj parametry pierścienia
            Polynomial.Init(q, t, modulusPoly);

            var sw = new Stopwatch();
            var res = new BenchmarkResult
            {
                ModulusDegree = modulusDegree,
                Q = q,
                T = t
            };

            // 1) KeyGen
            sw.Restart();
            KeyPair kp = null!;
            for (int i = 0; i < iterations; i++)
            {
                kp = KeyGenerator.GenerateKeyPair(modulusDegree);
            }
            sw.Stop();
            res.KeyGenTime = TimeSpan.FromTicks(sw.ElapsedTicks / iterations);

            // Przygotuj prosty komunikat
            var m = new Polynomial(1, 2, 3).ModPolynomial();

            // 2) Encrypt
            sw.Restart();
            Ciphertext ct = null!;
            for (int i = 0; i < iterations; i++)
            {
                ct = Encryptor.Encrypt(m, kp);
            }
            sw.Stop();
            res.EncryptTime = TimeSpan.FromTicks(sw.ElapsedTicks / iterations);

            // 3) Decrypt
            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                var dm = Encryptor.Decrypt(ct, kp.SecretKey);
            }
            sw.Stop();
            res.DecryptTime = TimeSpan.FromTicks(sw.ElapsedTicks / iterations);

            // 4) Add homomorficznie
            var ct2 = Encryptor.Encrypt(m, kp);
            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                var sum = Evaluator.Add(ct, ct2);
            }
            sw.Stop();
            res.AddTime = TimeSpan.FromTicks(sw.ElapsedTicks / iterations);

            // 5) Multiply homomorficznie
            sw.Restart();
            for (int i = 0; i < iterations; i++)
            {
                var prod = Evaluator.Multiply(ct, ct2, kp);
            }
            sw.Stop();
            res.MultiplyTime = TimeSpan.FromTicks(sw.ElapsedTicks / iterations);

            return res;
        }
        
        /// <summary>
        /// Przeprowadza serię benchmarków dla różnych parametrów i zwraca wyniki.
        /// </summary>
        /// <param name="parameterSets">
        /// Lista trójek: (modulusDegree, q, t, iterations).
        /// </param>
        public static List<BenchmarkResult> Sweep(
            IEnumerable<(int modulusDegree, BigInteger q, BigInteger t, int iterations)> parameterSets,
            Polynomial modulusTemplate = null!)
        {
            var results = new List<BenchmarkResult>();
            foreach (var (modulusDegree, q, t, iterations) in parameterSets)
            {
                // Przygotuj wielomian f(X) = X^N + 1 (lub inny, podany przez użytkownika)
                Polynomial f;
                if (modulusTemplate != null)
                {
                    // zakładamy, że template ma odpowiedni stopień
                    f = modulusTemplate;
                }
                else
                {
                    var coeffs = new BigInteger[modulusDegree + 1];
                    coeffs[0] = 1;
                    coeffs[modulusDegree] = 1;
                    f = new Polynomial(coeffs);
                }

                Console.WriteLine(
                    $"Benchmark: N={modulusDegree}, q={q}, t={t}, iter={iterations}");
                var res = Run(modulusDegree, q, t, f, iterations);
                results.Add(res);
            }

            return results;
        }

        /// <summary>
        /// Zapisuje wyniki benchmarku do pliku CSV.
        /// </summary>
        public static void ToCsv(
            this IEnumerable<BenchmarkResult> results,
            string path)
        {
            using var w = new StreamWriter(path);
            w.WriteLine("N,q,t,KeyGen_ms,Encrypt_ms,Decrypt_ms,Add_ms,Multiply_ms");
            foreach (var r in results)
            {
                w.WriteLine(
                    $"{r.ModulusDegree}," +
                    $"{r.Q}," +
                    $"{r.T}," +
                    $"{r.KeyGenTime.TotalMilliseconds:F3}," +
                    $"{r.EncryptTime.TotalMilliseconds:F3}," +
                    $"{r.DecryptTime.TotalMilliseconds:F3}," +
                    $"{r.AddTime.TotalMilliseconds:F3}," +
                    $"{r.MultiplyTime.TotalMilliseconds:F3}"
                );
            }
            Console.WriteLine($"Zapisano CSV do: {path}");
        }
    }
}
