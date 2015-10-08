/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId.Steam;
using Microsoft.Extensions.Internal;

namespace Microsoft.AspNet.Builder {
    public static class SteamAuthenticationExtensions {
        public static IApplicationBuilder UseSteamAuthentication([NotNull] this IApplicationBuilder app) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(new SteamAuthenticationOptions());
        }

        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] SteamAuthenticationOptions options) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(options);
        }

        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<SteamAuthenticationOptions> configuration) {
            var options = new SteamAuthenticationOptions();
            configuration(options);

            return app.UseSteamAuthentication(options);
        }
    }
}
