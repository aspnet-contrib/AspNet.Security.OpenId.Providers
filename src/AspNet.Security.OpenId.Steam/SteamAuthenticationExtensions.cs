/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId.Steam;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.OptionsModel;

namespace Microsoft.AspNet.Builder {
    public static class SteamAuthenticationExtensions {
        public static IServiceCollection ConfigureSteamAuthentication(
            [NotNull] this IServiceCollection services,
            [NotNull] Action<SteamAuthenticationOptions> configuration) {
            return services.Configure(configuration);
        }

        public static IApplicationBuilder UseSteamAuthentication([NotNull] this IApplicationBuilder app) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>();
        }

        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app,
            [NotNull] Action<SteamAuthenticationOptions> configuration) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(
                new ConfigureOptions<SteamAuthenticationOptions>(configuration));
        }
    }
}
