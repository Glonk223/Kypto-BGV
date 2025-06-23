using System.Numerics;

namespace BGV;

public class DepthTest
{
    public static int TestMultiplicativeDepth(
        Polynomial mPlain,
        KeyPair kpInitial,
        BigInteger[] Qchain
    )
    {
        int totalDepth = 0;

        for (int level = 0; level < Qchain.Length; level++)
        {
            BigInteger newQ = Qchain[level];
            Polynomial.Init(newQ, Polynomial.T, Polynomial.Modulus);
            var kp = Utils.SwitchKeys(kpInitial, newQ);
            
            Ciphertext ctA = Encryptor.Encrypt(mPlain, kpInitial);
            Ciphertext ctB = Encryptor.Encrypt(mPlain, kpInitial);
            
            ctA = Evaluator.ModulusSwitch(ctA, newQ);
            ctB = Evaluator.ModulusSwitch(ctB, newQ);

            while (true)
            { 
                ctA = Evaluator.Multiply(ctA, ctB, kp);
                var decrypted = Encryptor.Decrypt(ctA, kp.SecretKey);
                
                if (!decrypted.Equals(mPlain))
                {
                    break;
                }

                totalDepth++;
                if (totalDepth % 100 == 0)
                    Console.WriteLine($"Total depth: {totalDepth}");
            }
            Console.WriteLine("Jumped down in QChain");
        }

        return totalDepth;
    }
}