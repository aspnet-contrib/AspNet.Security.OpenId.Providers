/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.OptionsModel;

namespace Microsoft.AspNet.Builder {
    public static class OpenIdAuthenticationExtensions {
        public static IServiceCollection ConfigureOpenIdAuthentication(
            [NotNull] this IServiceCollection services,
            [NotNull] Action<OpenIdAuthenticationOptions> configuration) {
            return services.Configure(configuration);
        }

        public static IApplicationBuilder UseOpenIdAuthentication([NotNull] this IApplicationBuilder app) {
            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>();
        }

        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<OpenIdAuthenticationOptions> configuration) {
            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>(
                new ConfigureOptions<OpenIdAuthenticationOptions>(configuration));
        }
    }
}
