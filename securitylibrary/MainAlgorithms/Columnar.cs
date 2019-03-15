using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        static List<List<int>> keys = new List<List<int>>();

        static void permute(int[] list, int k, int m)
        {
            int i;
            if (k == m)
            {
                List<int> newList = new List<int>();
                for (i = 0; i <= m; i++)
                {
                    //Console.Write("{0}", list[i]);
                    newList.Add(list[i]);
                }
                keys.Add(newList);
                //Console.Write(" ");
            }
            else
                for (i = k; i <= m; i++)
                {
                    int temp = list[k];
                    list[k] = list[i];
                    list[i] = temp;
                    permute(list, k + 1, m);
                    temp = list[k];
                    list[k] = list[i];
                    list[i] = temp;
                }
        }

        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> elements = new List<int>();
            List<int> correctKey = new List<int>();
            Columnar algorithm = new Columnar();
            for (int i = 1; i < 10; i++)
            {
                elements.Add(i);
                permute(elements.ToArray(), 0, elements.Count - 1);
            }
            foreach (List<int> possibleKey in keys)
            {
                string myCipherText = algorithm.Encrypt(plainText, possibleKey);
                if (myCipherText.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    correctKey = possibleKey;
                    break;
                }
            }
            return correctKey;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            cipherText = cipherText.ToLower();
            int keyLen = key.Count();
            int CLen = cipherText.Length;

            int dev;

            dev = CLen / keyLen;

            char[,] pl = new char[dev, keyLen];



            for (int i = 0; i < keyLen; i++)
            {
                int counter2 = 0;
                int startindex = ((key[i] - 1) * dev);
                for (int j = 0; j < dev; j++)
                {
                    if (counter2 == dev)
                        counter2 = 0;
                    char z = cipherText[startindex];
                    pl[counter2, i] = z;

                    counter2++;
                    startindex++;
                }
            }
            string result = "";
            char[] res = new char[CLen];
            for (int i = 0; i < dev; i++)
            {
                for (int j = 0; j < keyLen; j++)
                {
                    result += pl[i, j];
                }
            }
            result = result.ToLower();
            return result;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            plainText = plainText.ToLower();
            int keyLen = key.Count();
            int ptLen = plainText.Length;
            int count = 0;
            string x = "*";
            int dev = 0;
            char[,] pt;

            if (ptLen % keyLen == 0)
            {
                dev = ptLen / keyLen;
                pt = new char[dev, keyLen];
                int counter = 0;
                for (int i = 0; i < dev; i++)
                {
                    int j;
                    for (j = 0; j < keyLen; j++)
                    {
                        pt[i, j] = plainText[counter];
                        counter++;
                    }

                }

            }

            else
            {
                while (ptLen % keyLen != 0)
                {
                    ptLen++;
                    count++;
                    plainText += x;
                }

                dev = ptLen / keyLen;

                pt = new char[dev, keyLen];
                int counter = 0;
                for (int i = 0; i < dev; i++)
                {
                    int j;
                    for (j = 0; j < keyLen; j++)
                    {
                        pt[i, j] = plainText[counter];
                        counter++;
                    }

                }

            }


            char[] ciphertext = new char[ptLen];


            for (int i = 0; i < keyLen; i++)
            {
                int counter2 = 0;
                int startindex = ((key[i] - 1) * dev);
                for (int j = 0; j < dev; j++)
                {
                    if (startindex == pt.Length)
                        break;
                    ciphertext[startindex] = pt[counter2, i];
                    counter2++;
                    startindex++;
                }
            }


            string res = new string(ciphertext);
            StringBuilder myRes = new StringBuilder();
            foreach (char item in res)
            {
                if (item != '*')
                {
                    myRes.Append(item);
                }
            }
            res = res.ToUpper();
            return myRes.ToString().ToUpper();
        }
    }
}
