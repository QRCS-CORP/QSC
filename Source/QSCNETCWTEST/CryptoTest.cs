using System;
using QSCNETCW;

namespace QSCNETCWTEST
{
    public class CryptoTest
    {
        public static bool TestAES256CBC()
        {
            // SP800-38a F2.5

            const int BLOCK_SIZE = 16;
            const int NUM_BLOCKS = 4;

            byte[] key = Utilities.HexToBin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
            byte[] iv = Utilities.HexToBin("000102030405060708090A0B0C0D0E0F");
            byte[] exp = Utilities.HexToBin("F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D" +
                "39F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B");
            byte[] msg = Utilities.HexToBin("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51" +
                "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
            byte[] cblks = new byte[NUM_BLOCKS * BLOCK_SIZE];
            byte[] iv2 = new byte[BLOCK_SIZE];
            byte[] pblks = new byte[NUM_BLOCKS * BLOCK_SIZE];
            ulong outlen;
            bool success;

            outlen = 0;
            Utilities.ArrayCopy(iv, iv2);

            QSCNETCW.AES aes = new QSCNETCW.AES();
            aes.Initialize(key, iv, null, true, AesCipherType.Aes256);
            aes.CBCEncrypt(cblks, msg, NUM_BLOCKS * BLOCK_SIZE);

            success = Utilities.ArraysEqual(cblks, exp);

            if (success == true)
            {
                aes.Initialize(key, iv2, null, false, AesCipherType.Aes256);
                aes.CBCDecrypt(pblks, ref outlen, cblks, NUM_BLOCKS * BLOCK_SIZE);

                success = Utilities.ArraysEqual(pblks, msg);
            }

            aes.Destroy();

            return success;
        }

        public static bool TestAES256CTR()
        {
            // SP800-38a F5.5

            const int BLOCK_SIZE = 16;
            const int NUM_BLOCKS = 4;

            byte[] key = Utilities.HexToBin("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4");
            byte[] iv = Utilities.HexToBin("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
            byte[] exp = Utilities.HexToBin("601EC313775789A5B7A7F504BBF3D228F443E3CA4D62B59ACA84E990CACAF5C5" +
                "2B0930DAA23DE94CE87017BA2D84988DDFC9C58DB67AADA613C2DD08457941A6");
            byte[] msg = Utilities.HexToBin("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51" +
                "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
            byte[] cblks = new byte[NUM_BLOCKS * BLOCK_SIZE];
            byte[] iv2 = new byte[BLOCK_SIZE];
            byte[] pblks = new byte[NUM_BLOCKS * BLOCK_SIZE];
            bool success;

            Utilities.ArrayCopy(iv, iv2);

            QSCNETCW.AES aes = new QSCNETCW.AES();
            aes.Initialize(key, iv, null, true, AesCipherType.Aes256);
            aes.CTRBETransform(cblks, msg, NUM_BLOCKS * BLOCK_SIZE);

            success = Utilities.ArraysEqual(cblks, exp);

            if (success == true)
            {
                aes.Initialize(key, iv2, null, true, AesCipherType.Aes256);
                aes.CTRBETransform(pblks, cblks, NUM_BLOCKS * BLOCK_SIZE);

                success = Utilities.ArraysEqual(pblks, msg);
            }

            aes.Destroy();

            return success;
        }

        public static bool TestChaCha256()
        {
            const int BLOCK_SIZE = 64;
            const int NONCE_SIZE = 8;

            byte[] key = Utilities.HexToBin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D");
            byte[] iv = Utilities.HexToBin("0D74DB42A91077DE");
            byte[] exp = Utilities.HexToBin("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51" +
                "AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3");
            byte[] msg = new byte[BLOCK_SIZE];
            byte[] cblks = new byte[BLOCK_SIZE];
            byte[] iv2 = new byte[NONCE_SIZE];
            byte[] pblks = new byte[BLOCK_SIZE];
            bool success;

            Utilities.ArrayCopy(iv, iv2);

            QSCNETCW.CHACHA chacha = new QSCNETCW.CHACHA();
            chacha.Initialize(key, iv);
            chacha.Transform(cblks, msg, BLOCK_SIZE);

            success = Utilities.ArraysEqual(cblks, exp);

            if (success == true)
            {
                chacha.Initialize(key, iv2);
                chacha.Transform(pblks, cblks, BLOCK_SIZE);

                success = Utilities.ArraysEqual(pblks, msg);
            }

            chacha.Destroy();

            return success;
        }

        public static bool TestSHA2256()
        {
            const int BLOCK_SIZE = 32;

            byte[] exp = Utilities.HexToBin("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1");
            byte[] msg = Utilities.HexToBin("6162636462636465636465666465666765666768666768696768696A68696A6B" +
                "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071");
            byte[] res = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.SHA256 sha2 = new QSCNETCW.SHA256();
            sha2.Update(msg, (ulong)msg.LongLength);
            sha2.Finalize(res);

            success = Utilities.ArraysEqual(res, exp);
            sha2.Destroy();

            return success;
        }

        public static bool TestSHA2512()
        {
            const int BLOCK_SIZE = 64;

            byte[] exp = Utilities.HexToBin("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C335" +
                "96FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445");
            byte[] msg = Utilities.HexToBin("6162636462636465636465666465666765666768666768696768696A68696A6B" +
                "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071");
            byte[] res = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.SHA512 sha2 = new QSCNETCW.SHA512();
            sha2.Update(msg, (ulong)msg.LongLength);
            sha2.Finalize(res);

            success = Utilities.ArraysEqual(res, exp);
            sha2.Destroy();

            return success;
        }

        public static bool TestHKDF256()
        {
            const int OUTPUT_SIZE = 42;

            byte[] exp = Utilities.HexToBin("D03C9AB82C884B1DCFD3F4CFFD0E4AD1501915E5D72DF0E6D846D59F6CF78047" +
                "39958B5DF06BDE49DB6D");
            byte[] inf = Utilities.HexToBin("F0F1F2F3F4F5F6F7F8F9");
            byte[] key = Utilities.HexToBin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
            byte[] otp = new byte[OUTPUT_SIZE];
            bool success;

            QSCNETCW.HKDF.HKDF256Expand(otp, OUTPUT_SIZE, key, (ulong)key.LongLength, inf, (ulong)inf.LongLength);

            success = Utilities.ArraysEqual(otp, exp);

            return success;
        }

        public static bool TestHKDF512()
        {
            const int OUTPUT_SIZE = 42;

            byte[] exp = Utilities.HexToBin("7CE212EEB2A92270C4460A4728944B9B0EE9E060DE13C197853D37A20CE7184F" +
                "94390EAEA4C18CEF989D");
            byte[] inf = Utilities.HexToBin("F0F1F2F3F4F5F6F7F8F9");
            byte[] key = Utilities.HexToBin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
            byte[] otp = new byte[OUTPUT_SIZE];
            bool success;

            QSCNETCW.HKDF.HKDF512Expand(otp, OUTPUT_SIZE, key, (ulong)key.LongLength, inf, (ulong)inf.LongLength);

            success = Utilities.ArraysEqual(otp, exp);

            return success;
        }

        public static bool TestHMAC256()
        {
            const int MAC_SIZE = 32;

            byte[] exp = Utilities.HexToBin("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7");
            byte[] msg = Utilities.HexToBin("4869205468657265");
            byte[] key = Utilities.HexToBin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
            byte[] otp = new byte[MAC_SIZE];
            bool success;

            QSCNETCW.HMAC256 hmac = new QSCNETCW.HMAC256(key, (ulong)key.LongLength);
            hmac.Update(msg, (ulong)msg.LongLength);
            hmac.Finalize(otp);

            success = Utilities.ArraysEqual(otp, exp);
            hmac.Destroy();

            return success;
        }

        public static bool TestHMAC512() 
        {
            const int MAC_SIZE = 64;
                                            
            byte[] exp = Utilities.HexToBin("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDE" +
                "DAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854");
            byte[] msg = Utilities.HexToBin("4869205468657265");
            byte[] key = Utilities.HexToBin("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
            byte[] otp = new byte[MAC_SIZE];
            bool success;

            QSCNETCW.HMAC512 hmac = new QSCNETCW.HMAC512(key, (ulong)key.LongLength);
            hmac.Update(msg, (ulong)msg.LongLength);
            hmac.Finalize(otp);

            success = Utilities.ArraysEqual(otp, exp);
            hmac.Destroy();

            return success;
        }

        public static bool TestSHA3256()
        {
            const int BLOCK_SIZE = 32;

            byte[] exp = Utilities.HexToBin("41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376");
            byte[] msg = Utilities.HexToBin("6162636462636465636465666465666765666768666768696768696A68696A6B" +
                "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071");
            byte[] res = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.SHA3 sha3 = new QSCNETCW.SHA3();
            sha3.Initialize(KeccakRate.Rate256);
            sha3.Update(msg, (ulong)msg.LongLength);
            sha3.Finalize(res);

            success = Utilities.ArraysEqual(res, exp);
            sha3.Destroy();

            return success;
        }

        public static bool TestSHA3512()
        {
            const int BLOCK_SIZE = 64;

            byte[] exp = Utilities.HexToBin("04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636D" +
                "EE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E");
            byte[] msg = Utilities.HexToBin("6162636462636465636465666465666765666768666768696768696A68696A6B" +
                "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071");
            byte[] res = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.SHA3 sha3 = new QSCNETCW.SHA3();
            sha3.Initialize(KeccakRate.Rate512);
            sha3.Update(msg, (ulong)msg.LongLength);
            sha3.Finalize(res);

            success = Utilities.ArraysEqual(res, exp);
            sha3.Destroy();

            return success;
        }

        public static bool TestKMAC256()
        {
            const int BLOCK_SIZE = 64;

            byte[] cust = Utilities.HexToBin("4D7920546167676564204170706C69636174696F6E");
            byte[] exp = Utilities.HexToBin("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7" +
                "F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD");
            byte[] key = Utilities.HexToBin("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F");
            byte[] msg = Utilities.HexToBin("00010203");
            byte[] otp = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.KMAC kmac = new QSCNETCW.KMAC();
            kmac.Initialize(KeccakRate.Rate256, key, (ulong)key.LongLength, cust, (ulong)cust.LongLength);
            kmac.Update(msg, (ulong)msg.LongLength);
            kmac.Finalize(otp, (ulong)otp.LongLength);

            success = Utilities.ArraysEqual(otp, exp);
            kmac.Destroy();

            return success;
        }

        public static bool TestKMAC512()
        {
            const int BLOCK_SIZE = 64;

            byte[] cust = Utilities.HexToBin("4D7920546167676564204170706C69636174696F6E");
            byte[] exp = Utilities.HexToBin("C41F31CEE9851BAA915716C16F7670C7C137C1908BD9694DA80C679AA6EB5964" +
                "E76AD91F2018DE576524D84E0B0FC586C06B110ED6DB273A921FFC86D1C20CE8");
            byte[] key = Utilities.HexToBin("4D7920546167676564204170706C69636174696F6E");
            byte[] msg = Utilities.HexToBin("4D7920546167676564204170706C69636174696F6E4D79205461676765642041" +
                "70706C69636174696F6E");
            byte[] otp = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.KMAC kmac = new QSCNETCW.KMAC();
            kmac.Initialize(KeccakRate.Rate512, key, (ulong)key.LongLength, cust, (ulong)cust.LongLength);
            kmac.Update(msg, (ulong)msg.LongLength);
            kmac.Finalize(otp, (ulong)otp.LongLength);

            success = Utilities.ArraysEqual(otp, exp);
            kmac.Destroy();

            return success;
        }

        public static bool TestSHAKE256()
        {
            const int BLOCK_SIZE = 512;

            byte[] exp = Utilities.HexToBin("CD8A920ED141AA0407A22D59288652E9D9F1A7EE0C1E7C1CA699424DA84A904D" +
                "2D700CAAE7396ECE96604440577DA4F3AA22AEB8857F961C4CD8E06F0AE6610B" +
                "1048A7F64E1074CD629E85AD7566048EFC4FB500B486A3309A8F26724C0ED628" +
                "001A1099422468DE726F1061D99EB9E93604D5AA7467D4B1BD6484582A384317" +
                "D7F47D750B8F5499512BB85A226C4243556E696F6BD072C5AA2D9B69730244B5" +
                "6853D16970AD817E213E470618178001C9FB56C54FEFA5FEE67D2DA524BB3B0B" +
                "61EF0E9114A92CDBB6CCCB98615CFE76E3510DD88D1CC28FF99287512F24BFAF" +
                "A1A76877B6F37198E3A641C68A7C42D45FA7ACC10DAE5F3CEFB7B735F12D4E58" +
                "9F7A456E78C0F5E4C4471FFFA5E4FA0514AE974D8C2648513B5DB494CEA84715" +
                "6D277AD0E141C24C7839064CD08851BC2E7CA109FD4E251C35BB0A04FB05B364" +
                "FF8C4D8B59BC303E25328C09A882E952518E1A8AE0FF265D61C465896973D749" +
                "0499DC639FB8502B39456791B1B6EC5BCC5D9AC36A6DF622A070D43FED781F5F" +
                "149F7B62675E7D1A4D6DEC48C1C7164586EAE06A51208C0B791244D307726505" +
                "C3AD4B26B6822377257AA152037560A739714A3CA79BD605547C9B78DD1F596F" +
                "2D4F1791BC689A0E9B799A37339C04275733740143EF5D2B58B96A363D4E0807" +
                "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB");
            byte[] msg = Utilities.HexToBin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3");
            byte[] otp = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.SHAKE.Compute256(otp, (ulong)otp.LongLength, msg, (ulong)msg.LongLength);

            success = Utilities.ArraysEqual(otp, exp);

            return success;
        }

        public static bool TestSHAKE512()
        {
            const int BLOCK_SIZE = 512;

            byte[] exp = Utilities.HexToBin("9701303D390F51968C25B6EEE54816D19AB149A1C06B0625940BB8E04A1CECCD" +
                "D88010234F53ABBBAF181F49761A3ECEFAEE56DE7B59B5AAF0031E3C1552C9AC" +
                "40DFAF6AAC934FD644DBC4A3D753E1F3845A5901F415DFF2A88440F6A8F5688F" +
                "F26E68ECC6AD23ACF18E0A54BE745DB919FAB01F77A251D5F66B01E2426BF020" +
                "BC27A6DFF274DC987313A42F1AC159F481A46F5BFB53914C7E79191F491C7808" +
                "DE0EDF3BCA24FD7DFD713806C062326C16FFAC00D1F8E94BA2DA0DE06D5F1826" +
                "A5AE881313AAD40FD0F260822ABB83ACC72E86006B1B04C28A0A30EAEB39040E" +
                "BD0D4ADB76263BD1186464A5CBA30B4332C1ACC5328B989A998B5F5CA5184AE6" +
                "DDAD039A3117C05C9CB2EA4DF5F8A2E8BD945EE42CE1789CE568D2BD7263DDF5" +
                "6520D040BB406AD2D10DE2E3714D049381737CEA1AE05062650AFCE1B1DE1F77" +
                "B418C7F7C4B1A5C233EF78FFC1D67215BEFDDCFA8E4C1CA64FF547B21DE12E20" +
                "11D8214D0BBAB6645ED240313C4D86646BEC8F9D58B788227B535BFCB8B75448" +
                "94E4A4BCD6DA9BF182DCEDD60348BD62579C898DBA9A6B6AA9E87E9C29F5855F" +
                "57F138ACA68EB7B89DBE7DD09B217E94C4E57974E96A28868202D643F08DF096" +
                "21AE714C2B47365DC44F608B97B5C5E0791EBE3C245CCCC1B537030EEDAA096F" +
                "EF24013B7D401C9C7470375D97A6A26066CFB7B88E72F6D6B635E9F09DB2C007");
            byte[] msg = Utilities.HexToBin("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3" +
                "A3A3A3A3A3A3A3A3");
            byte[] otp = new byte[BLOCK_SIZE];
            bool success;

            QSCNETCW.SHAKE.Compute512(otp, (ulong)otp.LongLength, msg, (ulong)msg.LongLength);

            success = Utilities.ArraysEqual(otp, exp);

            return success;
        }
    }
}
