using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            StringBuilder repeatedkey = new StringBuilder();
            cipherText = cipherText.ToLower();
            int a = Convert.ToInt32('a');
            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = Convert.ToInt32(cipherText[i]) - a;
                int p = Convert.ToInt32(plainText[i]) - a;
                int k = (c - p);
                k %= 26;
                if (k < 0) k += 26;
                k += a;

                repeatedkey.Append(Convert.ToChar(k));

            }

            int keyEnd = -1;
            string firstPart;
            string secondPart;
            string pt;
            for (int i = 0; i < repeatedkey.Length; i++)
            {
                if (i * 2 + 2 < repeatedkey.Length)
                {
                    firstPart = repeatedkey.ToString().Substring(0, i + 1);
                    secondPart = repeatedkey.ToString().Substring(i + 1, i + 1);
                    pt = plainText.ToString().Substring(0, i + 1);

                    if (secondPart.Equals(pt))
                    {
                        keyEnd = i;
                    }
                }
                else break;
            }

            string key;
            if (keyEnd < 0)
            {
                key = repeatedkey.ToString();
            }
            else
            {
                key = repeatedkey.ToString().Substring(0, keyEnd + 1);
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {

            key = key.ToLower();
            cipherText = cipherText.ToLower();

            int klength = key.Length;

            string pl = string.Empty;
            char[] newpl = new char[cipherText.Length];
            int a = Convert.ToInt32('a');
            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = Convert.ToInt32(cipherText[i]) - a;
                if (c < 0) c += 26;
                int k = Convert.ToInt32(key[i]) - a;
                if (k < 0) k += 26;
                int p = (c - k);
                p %= 26;
                if (p < 0) p += 26;
                p += a;
                char temp = Convert.ToChar(p);
                key += temp;
                newpl[i] = temp;

            }

            char[] NewKey = new char[cipherText.Length];
            int count = 0;
            for (int i = 0; i < NewKey.Length; i++)
            {
                NewKey[i] = key[i];
                count++;
            }
            int j = 0;
            for (int i = count; i < cipherText.Length; i++)
            {
                NewKey[i] = newpl[j];
                j++;
            }

            Console.WriteLine(NewKey);

            for (int i = klength; i < cipherText.Length; i++)
            {
                int c = Convert.ToInt32(cipherText[i]) - a;
                int k = Convert.ToInt32(NewKey[i]) - a;
                int p = (c - k);
                p %= 26;
                if (p < 0) p += 26;
                p += a;

                char temp = Convert.ToChar(p);
                newpl[i] = temp;
            }
            pl = new string(newpl);
            return pl;
        }

        public string Encrypt(string plainText, string key)
        {
            char[] ciphertext = new char[plainText.Length];

            key += plainText;
            key = key.Substring(0, plainText.Length);
            int a = Convert.ToInt32('a');
            for (int i = 0; i < plainText.Length; i++)
            {
                int p = Convert.ToInt32(plainText[i]) - a;
                int k = Convert.ToInt32(key[i]) - a;
                int c = p + k;
                c %= 26;
                c += a;

                ciphertext[i] = Convert.ToChar(c);
            }
            string cipher = new string(ciphertext);
            return cipher.ToUpper();
        }
    }
}
