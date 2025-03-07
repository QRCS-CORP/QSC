using System;
using QSCNETCW;
using QSCNETCWTEST;

namespace QSCNETCWTEST
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("QSC Wrapper Tests");
            Console.WriteLine("Testing FIPS SP800-38a AES256");

            if (CryptoTest.TestAES256CBC() == true)
            {
                Console.WriteLine("AES256-CBC test: PASS");
            }
            else
            {
                Console.WriteLine("AES256-CBC test: FAIL");
            }

            if (CryptoTest.TestAES256CTR() == true)
            {
                Console.WriteLine("AES256-CTR test: PASS");
            }
            else
            {
                Console.WriteLine("AES256-CTR test: FAIL");
            }

            Console.WriteLine("Testing CHACHA-P20 256");

            if (CryptoTest.TestChaCha256() == true)
            {
                Console.WriteLine("CHACHA-P20 256 test: PASS");
            }
            else
            {
                Console.WriteLine("CHACHA-P20 256 test: FAIL");
            }

            Console.WriteLine("Testing SHA2");

            if (CryptoTest.TestSHA2256() == true)
            {
                Console.WriteLine("SHA2-256 test: PASS");
            }
            else
            {
                Console.WriteLine("SHA2-256 test: FAIL");
            }

            if (CryptoTest.TestSHA2512() == true)
            {
                Console.WriteLine("SHA2-512 test: PASS");
            }
            else
            {
                Console.WriteLine("SHA2-512 test: FAIL");
            }

            Console.WriteLine("Testing HKDF");

            if (CryptoTest.TestHKDF256() == true)
            {
                Console.WriteLine("HKDF-256 test: PASS");
            }
            else
            {
                Console.WriteLine("HKDF-256 test: FAIL");
            }

            if (CryptoTest.TestHKDF512() == true)
            {
                Console.WriteLine("HKDF-512 test: PASS");
            }
            else
            {
                Console.WriteLine("HKDF-512 test: FAIL");
            }

            Console.WriteLine("Testing HMAC");

            if (CryptoTest.TestHMAC256() == true)
            {
                Console.WriteLine("HMAC-256 test: PASS");
            }
            else
            {
                Console.WriteLine("HMAC-256 test: FAIL");
            }

            if (CryptoTest.TestHMAC512() == true)
            {
                Console.WriteLine("HMAC-512 test: PASS");
            }
            else
            {
                Console.WriteLine("HMAC-512 test: FAIL");
            }

            Console.WriteLine("Testing SHA3");

            if (CryptoTest.TestSHA3256() == true)
            {
                Console.WriteLine("SHA3-256 test: PASS");
            }
            else
            {
                Console.WriteLine("SHA3-256 test: FAIL");
            }

            if (CryptoTest.TestSHA3512() == true)
            {
                Console.WriteLine("SHA3-512 test: PASS");
            }
            else
            {
                Console.WriteLine("SHA3-512 test: FAIL");
            }

            Console.WriteLine("Testing KMAC");

            if (CryptoTest.TestKMAC256() == true)
            {
                Console.WriteLine("KMAC-256 test: PASS");
            }
            else
            {
                Console.WriteLine("KMAC-256 test: FAIL");
            }

            if (CryptoTest.TestKMAC512() == true)
            {
                Console.WriteLine("KMAC-512 test: PASS");
            }
            else
            {
                Console.WriteLine("KMAC-512 test: FAIL");
            }

            Console.WriteLine("Testing SHAKE");

            if (CryptoTest.TestSHAKE256() == true)
            {
                Console.WriteLine("SHAKE-256 test: PASS");
            }
            else
            {
                Console.WriteLine("SHAKE-256 test: FAIL");
            }

            if (CryptoTest.TestSHAKE512() == true)
            {
                Console.WriteLine("SHAKE-512 test: PASS");
            }
            else
            {
                Console.WriteLine("SHAKE-512 test: FAIL");
            }

            Console.WriteLine("Tests complete, press any key to exit.");
            Console.Read();

            return 0;
        }
    }
}
