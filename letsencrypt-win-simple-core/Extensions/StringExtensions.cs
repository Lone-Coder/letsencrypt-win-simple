﻿using System.IO;
using System.Linq;

namespace LetsEncrypt.ACME.Simple.Core.Extensions
{
    public static class StringExtensions
    {
        public static string CleanFileName(this string fileName)
            =>
                Path.GetInvalidFileNameChars()
                    .Aggregate(fileName, (current, c) => current.Replace(c.ToString(), string.Empty));
    }
}