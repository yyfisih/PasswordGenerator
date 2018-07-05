using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PasswordGenerator
{
    public static class PasswordGenEngine
    {
        public static string GeneratePassword(int length)
        {
            if (length < 3)
            {
                throw new ArgumentException("length too short", "length");
            }

            using (var provider = new RNGCryptoServiceProvider())
            {
                var limit = GetRandomLength(length - 2, provider);
                var passowrd = GetRandomString(limit, "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray(), provider);

                limit = GetRandomLength(length - 1 - passowrd.Length, provider);
                passowrd += GetRandomString(limit, "abcdefghijklmnopqrstuvwxyz".ToCharArray(), provider);

                limit = length - passowrd.Length;
                passowrd += GetRandomString(limit, "0123456789".ToCharArray(), provider);

                var result = passowrd.ToCharArray();
                Shuffle(result, provider);
                return string.Join(string.Empty, result);
            }
        }

        public static PasswordComplianceError Validate(this string password, int lowerBound, int uppderBound)
        {
            if (string.IsNullOrEmpty(password) || password.Length < lowerBound)
            {
                return PasswordComplianceError.TooShort;
            }

            if (password.Length > uppderBound)
            {
                return PasswordComplianceError.TooLong;
            }

            var dm = Regex.Match(password, @"/\d+/", RegexOptions.ECMAScript);
            var am = Regex.Match(password, @"/[a-z]+/", RegexOptions.Singleline);


            if (!Regex.IsMatch(password, @"\d+", RegexOptions.ECMAScript)
                || !Regex.IsMatch(password, @"[a-z]+", RegexOptions.ECMAScript)
                || !Regex.IsMatch(password, @"[A-Z]+", RegexOptions.ECMAScript))

            {
                return PasswordComplianceError.TooWeak;
            }

            return PasswordComplianceError.NoError;
        }


        private static int GetRandomLength(int limit, RNGCryptoServiceProvider provider)
        {
            var box = new byte[1];

            do
            {
                provider.GetBytes(box);
            } while (!(box[0] < limit * (byte.MaxValue / limit)));

            var length = box[0] % limit;

            return length == 0 ? 1 : length;
        }

        /// Following solution inspired by CodesInChaos in 
        /// https://stackoverflow.com/questions/1344221/how-can-i-generate-random-alphanumeric-strings-in-c/13416143#13416143
        private static string GetRandomString(int length, char[] characterSet, RNGCryptoServiceProvider provider)
        {
            var bytes = new byte[length * 8];
            provider.GetBytes(bytes);
            var result = new char[length];
            for (var i = 0; i < length; i++)
            {
                var value = BitConverter.ToUInt64(bytes, i * 8);
                result[i] = characterSet[value % (uint) characterSet.Length];
            }

            return new string(result);
        }

        /// Following solution inspired by CodesInChaos in grenade
        /// in https://stackoverflow.com/questions/273313/randomize-a-listt
        public static void Shuffle<T>(this IList<T> list, RNGCryptoServiceProvider provider)
        {
            var n = list.Count;
            while (n > 1)
            {
                var box = new byte[1];
                do
                {
                    provider.GetBytes(box);
                } while (!(box[0] < n * (byte.MaxValue / n)));

                var k = box[0] % n;
                n--;
                var value = list[k];
                list[k] = list[n];
                list[n] = value;
            }
        }
    }

    public enum PasswordComplianceError
    {
        /// <summary>
        ///     No error found
        /// </summary>
        NoError = 0,

        /// <summary>
        ///     Password must not be the same as the user's last 6 passwords
        /// </summary>
        RepeatedInHistory = 1,

        /// <summary>
        ///     Password must have minimum of 9 characters
        /// </summary>
        TooShort = 2,

        /// <summary>
        ///     Password should not contains keywords like username etc.
        /// </summary>
        KeywordFound = 3,

        /// <summary>
        ///     Password must have:
        ///     One of which must be lowercase
        ///     One of which must be uppercase
        ///     One of which must be a number
        /// </summary>
        TooWeak = 4,

        /// <summary>
        ///     Password not allowed in external system (like BCI)
        /// </summary>
        UsedInExternalSystem = 5,

        /// <summary>
        ///     Password must have maximum of 30 characters, this is limited by db
        /// </summary>
        TooLong = 6
    }
}