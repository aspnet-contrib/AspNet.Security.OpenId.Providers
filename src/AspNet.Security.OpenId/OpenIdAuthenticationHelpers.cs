/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OpenId {
    internal static class OpenIdAuthenticationHelpers {
        public static IDictionary<string, StringValues> ToDictionary(this IEnumerable<KeyValuePair<string, StringValues>> collection) {
            if (collection == null) {
                throw new ArgumentNullException(nameof(collection));
            }

            return collection.ToDictionary(item => item.Key, item => item.Value);
        }
    }
}
