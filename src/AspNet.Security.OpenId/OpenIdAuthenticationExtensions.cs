/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using Microsoft.Framework.Internal;

namespace Microsoft.AspNet.Builder {
    public static class OpenIdAuthenticationExtensions {
        public static IApplicationBuilder UseOpenIdAuthentication([NotNull] this IApplicationBuilder app) {
            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>(new OpenIdAuthenticationOptions());
        }

        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] OpenIdAuthenticationOptions options) {
            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>(options);
        }

        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIdAuthenticationOptions> configuration) {
            var options = new OpenIdAuthenticationOptions();
            configuration(options);

            return app.UseOpenIdAuthentication(options);
        }
    }
}
