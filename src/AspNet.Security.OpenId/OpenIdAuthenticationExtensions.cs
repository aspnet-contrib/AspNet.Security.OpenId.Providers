/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using JetBrains.Annotations;
using Microsoft.Extensions.Options;

namespace Microsoft.AspNetCore.Builder {
    /// <summary>
    /// Exposes convenient extensions that can be used to add an instance
    /// of the OpenID authentication middleware in an ASP.NET 5 pipeline.
    /// </summary>
    public static class OpenIdAuthenticationExtensions {
        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationMiddleware{TOptions}"/> to the specified
        /// <see cref="IApplicationBuilder"/>, which enables OpenID2 authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
        /// <param name="options">The <see cref="OpenIdAuthenticationOptions"/> used to configure the OAuth2 options.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] OpenIdAuthenticationOptions options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>(Options.Create(options));
        }

        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationMiddleware{TOptions}"/> to the specified
        /// <see cref="IApplicationBuilder"/>, which enables OpenID2 authentication capabilities.
        /// </summary>
        /// <param name="app">The <see cref="IApplicationBuilder"/>.</param>
        /// <param name="configuration">The delegate used to configure the OAuth2 options.</param>
        /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIdAuthenticationOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OpenIdAuthenticationOptions();
            configuration(options);

            return app.UseOpenIdAuthentication(options);
        }
    }
}
