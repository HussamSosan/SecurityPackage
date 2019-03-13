using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();

            List<int> plainSample = new List<int>();
            List<int> cipherSample = new List<int>();
            List<int> plainInvers = new List<int>();

            int d = 0;
            bool dValid = false;
            int x=0;
            int y=0;
            for (x=0;x<plainText.Count;x+=2)
            {
                for (y = 0; y < plainText.Count; y += 2)
                {
                    if (x == y)
                    {
                        continue;
                    }
                    plainSample.Clear();
                    plainSample.Add(plainText[x]);
                    plainSample.Add(plainText[y]);
                    plainSample.Add(plainText[x + 1]);
                    plainSample.Add(plainText[y + 1]);

                    d = plainSample[0] * plainSample[3] - plainSample[1] * plainSample[2];

                    d %= 26;
                    if (d < 0) d += 26;

                    if (d == 1)
                    {
                        d = 1;
                        dValid = true;
                    }
                    else if (d == 3)
                    {
                        d = 9;
                        dValid = true;
                    }
                    else if (d == 5)
                    {
                        d = 21;
                        dValid = true;
                    }
                    else if (d == 7)
                    {
                        d = 15;
                        dValid = true;
                    }
                    else if (d == 9)
                    {
                        d = 3;
                        dValid = true;
                    }
                    else if (d == 11)
                    {
                        d = 19;
                        dValid = true;
                    }
                    else if (d == 15)
                    {
                        d = 7;
                        dValid = true;
                    }
                    else if (d == 17)
                    {
                        d = 23;
                        dValid = true;
                    }
                    else if (d == 19)
                    {
                        d = 11;
                        dValid = true;
                    }
                    else if (d == 21)
                    {
                        d = 5;
                        dValid = true;
                    }
                    else if (d == 23)
                    {
                        d = 17;
                        dValid = true;
                    }
                    else if (d == 25)
                    {
                        d = 25;
                        dValid = true;
                    }

                    if (dValid)
                    {
                        break;
                    }
                }
                if (dValid)
                {
                    break;
                }
            }

            if (dValid == false) throw new InvalidAnlysisException();

            int p1, p2, p3, p4;

            p1 = (plainSample[3] * d) % 26;
            p2 = (-1 * plainSample[1] * d) % 26;
            p3 = (-1 * plainSample[2] * d) % 26;
            p4 = (plainSample[0] * d) % 26;

            if (p1 < 0) p1 += 26;
            if (p2 < 0) p2 += 26;
            if (p3 < 0) p3 += 26;
            if (p4 < 0) p4 += 26;

            plainInvers.Add(p1);
            plainInvers.Add(p2);
            plainInvers.Add(p3);
            plainInvers.Add(p4);

            int k1, k2, k3, k4 = 0;

            cipherSample.Add(cipherText[x]);
            cipherSample.Add(cipherText[y]);
            cipherSample.Add(cipherText[x + 1]);
            cipherSample.Add(cipherText[y + 1]);


            k1 = cipherSample[0] * plainInvers[0] + cipherSample[1] * plainInvers[2];
            k2 = cipherSample[0] * plainInvers[1] + cipherSample[1] * plainInvers[3];
            k3 = cipherSample[2] * plainInvers[0] + cipherSample[3] * plainInvers[2];
            k4 = cipherSample[2] * plainInvers[1] + cipherSample[3] * plainInvers[3];

            k1 %= 26;
            k2 %= 26;
            k3 %= 26;
            k4 %= 26;

            key.Add(k1);
            key.Add(k2);
            key.Add(k3);
            key.Add(k4);

            return key;
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            List<int> plainText = new List<int>();
            List<int> kInverse = new List<int>();
            if(key.Count==4)
            {
                int d = key[0] * key[3] - key[1] * key[2];
                d %= 26;

                if (d < 0) d += 26;
                if (d == 1) d = 1;
                else if (d == 3) d = 9;
                else if (d == 5) d = 21;
                else if (d == 7) d = 15;
                else if (d == 9) d = 3;
                else if (d == 11) d = 19;
                else if (d == 15) d = 7;
                else if (d == 17) d = 23;
                else if (d == 19) d = 11;
                else if (d == 21) d = 5;
                else if (d == 23) d = 17;
                else if (d == 25) d = 25;
                else throw new Exception();

                int k1, k2, k3, k4;

                k1 = (key[3] * d) % 26;
                k2 = (-1 * key[1] * d) % 26;
                k3 = (-1 * key[2] * d) % 26;
                k4 = (key[0] * d) % 26;

                if (k1 < 0) k1 += 26;
                if (k2 < 0) k2 += 26;
                if (k3 < 0) k3 += 26;
                if (k4 < 0) k4 += 26;

                kInverse.Add(k1);
                kInverse.Add(k2);
                kInverse.Add(k3);
                kInverse.Add(k4);

                for (int i = 0; i < cipherText.Count; i += 2)
                {
                    int p1, p2 = 0;
                    p1 = (cipherText[i] * kInverse[0] + cipherText[i + 1] * kInverse[1]) % 26;
                    p2 = (cipherText[i] * kInverse[2] + cipherText[i + 1] * kInverse[3]) % 26;
                    plainText.Add(p1);
                    plainText.Add(p2);
                }

            }

            else if(key.Count == 9)
            {
                int k0, k1, k2 = 0;

                k0 = key[0] * (key[4] * key[8] - key[5] * key[7]);
                k1 = key[1] * (key[3] * key[8] - key[5] * key[6]);
                k2 = key[2] * (key[3] * key[7] - key[4] * key[6]);

                int d = k0 - k1 + k2;
                d %= 26;

                if (d < 0) d += 26;

                if (d == 1) d = 1;
                else if (d == 3) d = 9;
                else if (d == 5) d = 21;
                else if (d == 7) d = 15;
                else if (d == 9) d = 3;
                else if (d == 11) d = 19;
                else if (d == 15) d = 7;
                else if (d == 17) d = 23;
                else if (d == 19) d = 11;
                else if (d == 21) d = 5;
                else if (d == 23) d = 17;
                else if (d == 25) d = 25;
                else throw new Exception();

                int[] adj = new int[9];

                adj[0] = key[4] * key[8] - key[5] * key[7];
                adj[1] = key[3] * key[8] - key[5] * key[6];
                adj[2] = key[3] * key[7] - key[4] * key[6];
                adj[3] = key[1] * key[8] - key[7] * key[2];
                adj[4] = key[0] * key[8] - key[2] * key[6];
                adj[5] = key[0] * key[7] - key[6] * key[1];
                adj[6] = key[1] * key[5] - key[2] * key[4];
                adj[7] = key[0] * key[5] - key[2] * key[3];
                adj[8] = key[0] * key[4] - key[1] * key[3];

                adj[1] *= -1;
                adj[3] *= -1;
                adj[5] *= -1;
                adj[7] *= -1;

                for (int i = 0; i < adj.Length; i++)
                {
                    adj[i] %= 26;
                }

                for (int i=0;i<adj.Length;i++)
                {
                    adj[i] *= d;
                }


                for (int i = 0; i < adj.Length; i++)
                {
                    adj[i] %= 26;
                }

                List<int> kInv = new List<int>();

                kInv.Add(adj[0]);
                kInv.Add(adj[3]);
                kInv.Add(adj[6]);
                kInv.Add(adj[1]);
                kInv.Add(adj[4]);
                kInv.Add(adj[7]);
                kInv.Add(adj[2]);
                kInv.Add(adj[5]);
                kInv.Add(adj[8]);

                for(int i=0;i<kInv.Count;i++)
                {
                    if (kInv[i] < 0) kInv[i] += 26;
                }

                for (int i = 0; i < cipherText.Count; i += 3)
                {
                    int p1, p2, p3 = 0;
                    p1 = kInv[0] * cipherText[i] + kInv[1] * cipherText[i + 1] + kInv[2] * cipherText[i + 2];
                    p2 = kInv[3] * cipherText[i] + kInv[4] * cipherText[i + 1] + kInv[5] * cipherText[i + 2];
                    p3 = kInv[6] * cipherText[i] + kInv[7] * cipherText[i + 1] + kInv[8] * cipherText[i + 2];
                    p1 %= 26;
                    p2 %= 26;
                    p3 %= 26;
                    plainText.Add(p1);
                    plainText.Add(p2);
                    plainText.Add(p3);
                }

            }

            return plainText;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipherText = new List<int>();
            if(key.Count == 4)
            {
                for(int i=0;i<plainText.Count;i+=2)
                {
                    int c1, c2 = 0;
                    c1 = (plainText[i] * key[0] + plainText[i + 1] * key[1]) % 26 ;
                    c2 = (plainText[i] * key[2] + plainText[i + 1] * key[3]) % 26;
                    cipherText.Add(c1);
                    cipherText.Add(c2);
                }
            }
            else if (key.Count == 9)
            {
                for(int i=0;i<plainText.Count;i+=3)
                {
                    int c1, c2, c3 = 0;
                    c1 = key[0] * plainText[i] + key[1] * plainText[i + 1] + key[2] * plainText[i + 2];
                    c2 = key[3] * plainText[i] + key[4] * plainText[i + 1] + key[5] * plainText[i + 2];
                    c3 = key[6] * plainText[i] + key[7] * plainText[i + 1] + key[8] * plainText[i + 2];
                    c1 %= 26;
                    c2 %= 26;
                    c3 %= 26;
                    cipherText.Add(c1);
                    cipherText.Add(c2);
                    cipherText.Add(c3);
                }
            }
            return cipherText;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            List<int> key = new List<int>();
            List<int> plainSample = new List<int>();
            List<int> cipherSample = new List<int>();
            int x = 0;
            int y = 0;
            int z = 0;
            int d = 0;
            bool dValid = false;

            for(x=0;x<3;x++)
            {
                for(y=0;y<3;y++)
                {
                    for (z = 0; z < 3; z++)
                    {
                        if (x == y || x == z || y == z)
                        {
                            continue;
                        }

                        plainSample.Add(plainText[x]);
                        plainSample.Add(plainText[x + 3]);
                        plainSample.Add(plainText[x + 6]);
                        plainSample.Add(plainText[y]);
                        plainSample.Add(plainText[y + 3]);
                        plainSample.Add(plainText[y + 6]);
                        plainSample.Add(plainText[z]);
                        plainSample.Add(plainText[z + 3]);
                        plainSample.Add(plainText[z + 6]);

                        int p0, p1, p2 = 0;

                        p0 = plainSample[0] * (plainSample[4] * plainSample[8] - plainSample[5] * plainSample[7]);
                        p1 = plainSample[1] * (plainSample[3] * plainSample[8] - plainSample[5] * plainSample[6]);
                        p2 = plainSample[2] * (plainSample[3] * plainSample[7] - plainSample[4] * plainSample[6]);

                        d = p0 - p1 + p2;
                        d %= 26;

                        if (d < 0) d += 26;

                        if (d == 1)
                        {
                            d = 1;
                            dValid = true;
                        }
                        else if (d == 3)
                        {
                            d = 9;
                            dValid = true;
                        }
                        else if (d == 5)
                        {
                            d = 21;
                            dValid = true;
                        }
                        else if (d == 7)
                        {
                            d = 15;
                            dValid = true;
                        }
                        else if (d == 9)
                        {
                            d = 3;
                            dValid = true;
                        }
                        else if (d == 11)
                        {
                            d = 19;
                            dValid = true;
                        }
                        else if (d == 15)
                        {
                            d = 7;
                            dValid = true;
                        }
                        else if (d == 17)
                        {
                            d = 23;
                            dValid = true;
                        }
                        else if (d == 19)
                        {
                            d = 11;
                            dValid = true;
                        }
                        else if (d == 21)
                        {
                            d = 5;
                            dValid = true;
                        }
                        else if (d == 23)
                        {
                            d = 17;
                            dValid = true;
                        }
                        else if (d == 25)
                        {
                            d = 25;
                            dValid = true;
                        }

                        if (dValid) break;
                    }
                    if (dValid) break;
                }
                if (dValid) break;
            }

            if(!dValid) throw new InvalidAnlysisException();

            cipherSample.Add(cipherText[x]);
            cipherSample.Add(cipherText[x + 3]);
            cipherSample.Add(cipherText[x + 6]);
            cipherSample.Add(cipherText[y]);
            cipherSample.Add(cipherText[y + 3]);
            cipherSample.Add(cipherText[y + 6]);
            cipherSample.Add(cipherText[z]);
            cipherSample.Add(cipherText[z + 3]);
            cipherSample.Add(cipherText[z + 6]);

            int[] adj = new int[9];

            adj[0] = plainSample[4] * plainSample[8] - plainSample[5] * plainSample[7];
            adj[1] = plainSample[3] * plainSample[8] - plainSample[5] * plainSample[6];
            adj[2] = plainSample[3] * plainSample[7] - plainSample[4] * plainSample[6];
            adj[3] = plainSample[1] * plainSample[8] - plainSample[7] * plainSample[2];
            adj[4] = plainSample[0] * plainSample[8] - plainSample[2] * plainSample[6];
            adj[5] = plainSample[0] * plainSample[7] - plainSample[6] * plainSample[1];
            adj[6] = plainSample[1] * plainSample[5] - plainSample[2] * plainSample[4];
            adj[7] = plainSample[0] * plainSample[5] - plainSample[2] * plainSample[3];
            adj[8] = plainSample[0] * plainSample[4] - plainSample[1] * plainSample[3];

            adj[1] *= -1;
            adj[3] *= -1;
            adj[5] *= -1;
            adj[7] *= -1;

            for (int i = 0; i < adj.Length; i++)
            {
                adj[i] %= 26;
            }

            for (int i = 0; i < adj.Length; i++)
            {
                adj[i] *= d;
            }


            for (int i = 0; i < adj.Length; i++)
            {
                adj[i] %= 26;
            }

            List<int> pInv = new List<int>();

            pInv.Add(adj[0]);
            pInv.Add(adj[3]);
            pInv.Add(adj[6]);
            pInv.Add(adj[1]);
            pInv.Add(adj[4]);
            pInv.Add(adj[7]);
            pInv.Add(adj[2]);
            pInv.Add(adj[5]);
            pInv.Add(adj[8]);

            for (int i = 0; i < pInv.Count; i++)
            {
                if (pInv[i] < 0) pInv[i] += 26;
            }

            for (int i = 0; i < pInv.Count; i += 3)
            {
                int k1, k2, k3 = 0;
                k1 = cipherSample[i] * pInv[0] + cipherSample[i+1] * pInv[3] + cipherSample[i+2] * pInv[6];
                k2 = cipherSample[i] * pInv[1] + cipherSample[i+1] * pInv[4] + cipherSample[i+2] * pInv[7];
                k3 = cipherSample[i] * pInv[2] + cipherSample[i+1] * pInv[5] + cipherSample[i+2] * pInv[8];
                k1 %= 26;
                k2 %= 26;
                k3 %= 26;
                key.Add(k1);
                key.Add(k2);
                key.Add(k3);
            }

            return key;
        }

    }
}
