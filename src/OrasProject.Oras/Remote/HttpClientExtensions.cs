﻿using System.Net.Http;

namespace Oras.Remote
{
    internal static class HttpClientExtensions
    {
        public static void AddUserAgent(this HttpClient client)
        {
            client.DefaultRequestHeaders.Add("User-Agent", new string[] { "oras-dotnet" });
        }
    }
}