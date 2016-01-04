/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId.Steam;
using Microsoft.Extensions.Internal;

namespace Microsoft.AspNet.Builder {
    /// <summary>
    /// Exposes convenient extensions that can be used to add an instance
    /// of the Steam authentication middleware in an ASP.NET 5 pipeline.
    /// </summary>
    public static class SteamAuthenticationExtensions {
        /// <summary>
        /// Adds <see cref="SteamAuthenticationMiddleware"/> to the specified
        /// <see cref="IApplicationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseSteamAuthentication([NotNull] this IApplicationBuilder app) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(new SteamAuthenticationOptions());
        }

        /// <summary>
        /// Adds <see cref="SteamAuthenticationMiddleware"/> to the specified
        /// <see cref="IApplicationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
        /// <param name="options">The <see cref="SteamAuthenticationOptions"/> used to configure the Steam options.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] SteamAuthenticationOptions options) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(options);
        }


        /// <summary>
        /// Adds <see cref="SteamAuthenticationMiddleware"/> to the specified
        /// <see cref="IApplicationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
        /// <param name="configuration">The delegate used to configure the Steam options.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<SteamAuthenticationOptions> configuration) {
            var options = new SteamAuthenticationOptions();
            configuration(options);

            return app.UseSteamAuthentication(options);
        }
    }
}
