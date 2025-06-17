using System.Numerics;

namespace BGV;

public class Program
{
    public static void Main(string[] args)
    {
        var configs = new List<(int, BigInteger, BigInteger, int)>
        {
            // N,                         q,                             t, iterations
            (512,  BigInteger.Parse("1152921504606846977"), (BigInteger)256,  20),
            (1024, BigInteger.Parse("1152921504606846977"), (BigInteger)256,  20),
            (2048, BigInteger.Parse("1152921504606846977"), (BigInteger)256,  20),
            (2048, BigInteger.Parse("4611686018427387847"), (BigInteger)512,  20),
        };
    
        var results = Benchmark.Sweep(configs);
        
        foreach (var r in results)
            Console.WriteLine(r);
    
        results.ToCsv("bgv_benchmark_results.csv");
    }
}