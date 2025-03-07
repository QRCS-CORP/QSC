using System;

namespace QSCNETCWTEST
{
    public class Utilities
    {
        public static byte[] HexToBin(string hex)
        {
            byte[] result = new byte[hex.Length / 2];

            if ((hex.Length & 1) != 0)
            {
                throw new ArgumentException("Invalid hex string (odd length)");
            }

            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }

            return result;
        }

        public static bool ArraysEqual(byte[] a, byte[] b)
        {
            bool res;

            res = true;

            if (a != null && b != null && a.Length == b.Length)
            {
                for (int i = 0; i < a.Length; ++i)
                {
                    if (a[i] != b[i])
                    {
                        res = false;
                        break;
                    }
                }
            }
            else
            {
                res = false;
            }

            return res;
        }

        public static void ArrayCopy(byte[] input, byte[] output)
        {
            if (input != null && output != null && output.Length >= input.Length)
            {
                for (int i = 0; i < input.Length; ++i)
                {
                    output[i] = input[i];
                }
            }
        }
    }
}
