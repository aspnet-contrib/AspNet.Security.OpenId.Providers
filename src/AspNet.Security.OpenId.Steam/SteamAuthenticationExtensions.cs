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

        public static IServiceCollection ConfigureSteamAuthentication(
            [NotNull] this IServiceCollection services, [NotNull] string instance,
            [NotNull] Action<SteamAuthenticationOptions> configuration) {
            return services.Configure(configuration, instance);
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

        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app, [NotNull] string instance) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(
                new ConfigureOptions<SteamAuthenticationOptions>(options => { }) { Name = instance });
        }

        public static IApplicationBuilder UseSteamAuthentication(
            [NotNull] this IApplicationBuilder app, [NotNull] string instance,
            [NotNull] Action<SteamAuthenticationOptions> configuration) {
            return app.UseMiddleware<SteamAuthenticationMiddleware>(
                new ConfigureOptions<SteamAuthenticationOptions>(configuration) { Name = instance });
        }
    }
}
