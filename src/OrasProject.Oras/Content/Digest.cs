// Copyright The ORAS Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using OrasProject.Oras.Content.Exceptions;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace OrasProject.Oras.Content;

internal static partial class Digest
{
    // Regular expression pattern for validating digest strings
    // The pattern matches the following format:
    // <algorithm>:<base64url-encoded digest>
    // Explanation:
    // - ^[a-z0-9]+: The algorithm part, consisting of lowercase letters
    //          and digits, followed by a colon.
    // - (?:[.+_-][a-z0-9]+)*: Optional segments of a dot, plus, underscore,
    //           or hyphen followed by lowercase letters and digits.
    // - :[a-zA-Z0-9=_-]+$: The digest part, consisting of base64url-encoded
    //          characters (letters, digits, equals, underscore, hyphen).
    // For more details, refer to the distribution specification:
    // https://github.com/opencontainers/image-spec/blob/v1.1.1/descriptor.md#digests
    [GeneratedRegex(@"^[a-z0-9]+(?:[.+_-][a-z0-9]+)*:[a-zA-Z0-9=_-]+$", RegexOptions.Compiled)]
    private static partial Regex DigestRegex();

    // List of registered and supported algorithms as per the specification
    private static readonly HashSet<string> _supportedAlgorithms = ["sha256", "sha512"];

    /// <summary>
    /// Verifies the digest header and throws an exception if it is invalid.
    /// </summary>
    /// <param name="digest">The digest to validate</param>
    /// <returns>The validated digest as a string</returns>
    /// <exception cref="InvalidDigestException">Thrown when the digest is invalid</exception>
    internal static string Validate(string digest)
    {
        return TryValidate(digest.AsSpan(), out var error)
            ? digest
            : throw new InvalidDigestException(error);
    }

    /// <summary>
    /// Tries to validate a digest without throwing an exception.
    /// </summary>
    /// <param name="digest">The digest to validate</param>
    /// <param name="error">The error message if validation fails</param>
    /// <returns>True if the digest is valid, false otherwise</returns>
    internal static bool TryValidate(string digest, out string error)
    {
        return TryValidate(digest.AsSpan(), out error);
    }

    /// <summary>
    /// Tries to validate a digest without throwing an exception.
    /// </summary>
    /// <param name="digest">The digest to validate as ReadOnlySpan</param>
    /// <param name="error">The error message if validation fails</param>
    /// <returns>True if the digest is valid, false otherwise</returns>
    private static bool TryValidate(ReadOnlySpan<char> digest, out string error)
    {
        if (digest.IsEmpty)
        {
            error = "Digest is null or empty";
            return false;
        }

        if (!DigestRegex().IsMatch(digest))
        {
            error = $"Invalid digest: {digest}";
            return false;
        }

        // Find the index of the colon that separates algorithm from value
        int colonIndex = digest.IndexOf(':');
        if (colonIndex <= 0) // Shouldn't happen if regex passed, but check anyway
        {
            error = $"Invalid digest format (missing algorithm): {digest}";
            return false;
        }

        // Extract just the algorithm part without allocating a new string array
        var algorithmSpan = digest[..colonIndex];
        string algorithm = algorithmSpan.ToString(); // Convert to string for HashSet check

        if (!_supportedAlgorithms.Contains(algorithm))
        {
            error = $"Unrecognized, unregistered or unsupported digest algorithm: {algorithm}";
            return false;
        }

        error = string.Empty;
        return true;
    }

    /// <summary>
    /// Generates a SHA-256 digest from a byte array.
    /// </summary>
    /// <param name="content"></param>
    /// <returns></returns>
    internal static string ComputeSha256(byte[] content)
    {
        var hash = SHA256.HashData(content);
        var output = $"sha256:{Convert.ToHexString(hash)}";
        return output.ToLower();
    }
}
