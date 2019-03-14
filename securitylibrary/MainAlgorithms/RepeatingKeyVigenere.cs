using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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
            for (int i = 0; i < repeatedkey.Length; i++)
            {
                if (i * 2 + 2 < repeatedkey.Length)
                {
                    firstPart = repeatedkey.ToString().Substring(0, i + 1);
                    secondPart = repeatedkey.ToString().Substring(i + 1, i + 1);
                    if (firstPart.Equals(secondPart))
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
            cipherText = cipherText.ToLower();
            char[] NewKey = new char[cipherText.Length];
            char[] plainText = new char[cipherText.Length];
            char[] chars = new char[cipherText.Length];

            if (cipherText.Length > key.Length)
            {
                int i = 0;
                for (int j = 0; i < cipherText.Length; ++j)
                {
                    if (j == key.Length)
                        j = 0;

                    chars[i] = key[j];
                    i++;
                }

                NewKey = chars;
            }


            else
            {
                int i = 0;
                for (int y = 0; i < cipherText.Length; ++y)
                {
                    chars[i] = key[y];
                    i++;
                }
                NewKey = chars;
            }


            int a = Convert.ToInt32('a');
            for (int i = 0; i < cipherText.Length; i++)
            {
                int c = Convert.ToInt32(cipherText[i]) - a;
                int k = Convert.ToInt32(NewKey[i]) - a;
                int p = (c - k);
                p %= 26;
                if (p < 0) p += 26;
                p += a;

                plainText[i] = Convert.ToChar(p);

            }
            string plain = new string(plainText);
            return plain;
        }

        public string Encrypt(string plainText, string key)
        {
            char[] NewKey = new char[plainText.Length];
            char[] ciphertext = new char[plainText.Length];
            char[] chars = new char[plainText.Length];

            if (plainText.Length > key.Length)
            {
                int i = 0;
                for (int j = 0; i < plainText.Length; ++j)
                {
                    if (j == key.Length)
                        j = 0;

                    chars[i] = key[j];
                    i++;
                }

                NewKey = chars;
            }


            else
            {
                int i = 0;
                for (int y = 0; i < plainText.Length; ++y)
                {
                    chars[i] = key[y];
                    i++;
                }
                NewKey = chars;
            }


            int a = Convert.ToInt32('a');
            for (int i = 0; i < plainText.Length; i++)
            {
                int p = Convert.ToInt32(plainText[i]) - a;
                int k = Convert.ToInt32(NewKey[i]) - a;
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