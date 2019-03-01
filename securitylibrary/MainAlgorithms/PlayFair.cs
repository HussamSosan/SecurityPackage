using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {

            cipherText = cipherText.ToLower();
            key = key.ToLower();
            StringBuilder plainText = new StringBuilder();

            char[] matrix = new char[25];
            int indexPtr = 0;

            foreach (char letter in key)
            {
                if (!matrix.Contains<char>(letter))
                {
                    matrix[indexPtr] = letter;
                    indexPtr++;
                }
            }

            char letterToAppend = 'a';
            for (int i = 0; i < 25; i++)
            {
                if (letterToAppend == 'j')
                {
                    letterToAppend++;
                }
                if (!matrix.Contains<char>(letterToAppend))
                {
                    matrix[indexPtr] = letterToAppend;
                    indexPtr++;
                }
                letterToAppend++;
            }

            for (int i = 0; i <= cipherText.Length - 1; i += 2)
            {
                char firstLetter = cipherText[i];
                char secondLetter = cipherText[i + 1];

                int firstIndex;
                int secondIndex;
                for (firstIndex = 0; firstIndex < 25; firstIndex++)
                {
                    if (matrix[firstIndex] == firstLetter)
                    {
                        break;
                    }
                }
                for (secondIndex = 0; secondIndex < 25; secondIndex++)
                {
                    if (matrix[secondIndex] == secondLetter)
                    {
                        break;
                    }
                }


                int R1 = firstIndex / 5;
                int R2 = secondIndex / 5;

                int C1 = (firstIndex % 5);
                int C2 = (secondIndex % 5);

                if (R1 == R2)
                {
                    plainText.Append(C1 == 0 ? matrix[firstIndex + 4] : matrix[firstIndex - 1]);
                    plainText.Append(C2 == 0 ? matrix[secondIndex + 4] : matrix[secondIndex - 1]);
                }
                else if (C1 == C2)
                {
                    plainText.Append(firstIndex < 5 ? matrix[firstIndex + 20] : matrix[firstIndex - 5]);
                    plainText.Append(secondIndex < 5 ? matrix[secondIndex + 20] : matrix[secondIndex - 5]);
                }
                else
                {
                    if (R1 > R2)
                    {
                        plainText.Append(matrix[R1 * 5 + C2]);
                        plainText.Append(matrix[R2 * 5 + C1]);
                    }
                    else
                    {
                        plainText.Append(matrix[R1 * 5 + C2]);
                        plainText.Append(matrix[R2 * 5 + C1]);
                    }
                }
            }

            //for (int i = 0; i < plainText.Length; i++)
            //{
            //    if (plainText[i] == 'x')
            //    {
            //        plainText.Remove(i, 1);
            //        i--;
            //    }
            //}

            StringBuilder finalText = new StringBuilder();
            plainText.Append(" ");
            for (int i = 0; i < plainText.Length -1; i++)
            {
                if (plainText[i] == 'x' && plainText[i - 1] == plainText[i + 1] && i % 2 == 1)
                {
                    continue;
                }
                finalText.Append(plainText[i]);
            }


            if (finalText[finalText.Length - 1] == 'x')
            {
                finalText.Remove(finalText.Length - 1, 1);
            }

            return finalText.ToString();
        }

        public string Encrypt(string plainText, string key)
        {
            StringBuilder cipherText = new StringBuilder();

            char[] matrix = new char[25];
            int indexPtr = 0;

            foreach (char letter in key)
            {
                if (!matrix.Contains<char>(letter))
                {
                    matrix[indexPtr] = letter;
                    indexPtr++;
                }
            }

            char letterToAppend = 'a';
            for (int i = 0; i < 25; i++)
            {
                if (letterToAppend == 'j')
                {
                    letterToAppend++;
                }
                if (!matrix.Contains<char>(letterToAppend))
                {
                    matrix[indexPtr] = letterToAppend;
                    indexPtr++;
                }
                letterToAppend++;
            }

            for (int i = 0; i <= plainText.Length - 1; i += 2)
            {
                char firstLetter = plainText[i];
                char secondLetter = i == plainText.Length - 1 ? 'x' : plainText[i + 1];
                if (firstLetter == secondLetter)
                {
                    secondLetter = 'x';
                    i--;
                }

                if (firstLetter == 'j')
                {
                    firstLetter = 'i';
                }
                if (secondLetter == 'j')
                {
                    secondLetter = 'i';
                }

                int firstIndex;
                int secondIndex;
                for (firstIndex = 0; firstIndex < 25; firstIndex++)
                {
                    if (matrix[firstIndex] == firstLetter)
                    {
                        break;
                    }
                }
                for (secondIndex = 0; secondIndex < 25; secondIndex++)
                {
                    if (matrix[secondIndex] == secondLetter)
                    {
                        break;
                    }
                }


                int R1 = firstIndex / 5;
                int R2 = secondIndex / 5;

                int C1 = (firstIndex % 5);
                int C2 = (secondIndex % 5);

                if (R1 == R2)
                {
                    cipherText.Append(C1 == 4 ? matrix[firstIndex - 4] : matrix[firstIndex + 1]);
                    cipherText.Append(C2 == 4 ? matrix[secondIndex - 4] : matrix[secondIndex + 1]);
                }
                else if (C1 == C2)
                {
                    cipherText.Append(firstIndex >= 20 ? matrix[firstIndex - 20] : matrix[firstIndex + 5]);
                    cipherText.Append(secondIndex >= 20 ? matrix[secondIndex - 20] : matrix[secondIndex + 5]);
                }
                else
                {
                    if (R1 > R2)
                    {

                        cipherText.Append(matrix[R1 * 5 + C2]);
                        cipherText.Append(matrix[R2 * 5 + C1]);
                    }
                    else
                    {
                        cipherText.Append(matrix[R1 * 5 + C2]);
                        cipherText.Append(matrix[R2 * 5 + C1]);
                    }
                }
            }

            return cipherText.ToString();
        }
    }
}
