using System;
using AspNet.Security.OpenId;
using Microsoft.Framework.DependencyInjection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.OptionsModel;

namespace Microsoft.AspNet.Builder {
    public static class OpenIdAuthenticationExtensions {
        public static IServiceCollection ConfigureOpenIdAuthentication(
            [NotNull] this IServiceCollection services, [NotNull] string scheme,
            [NotNull] Action<OpenIdAuthenticationOptions> configuration) {
            return services.Configure<OpenIdAuthenticationOptions>(options => {
                options.AuthenticationScheme = scheme;
                options.Caption = scheme;

                configuration(options);
            }, scheme);
        }

        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app, [NotNull] string scheme) {
            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>(
                new ConfigureOptions<OpenIdAuthenticationOptions>(options => {
                    options.AuthenticationScheme = scheme;
                    options.Caption = scheme;
                }) { Name = scheme });
        }

        public static IApplicationBuilder UseOpenIdAuthentication(
            [NotNull] this IApplicationBuilder app, [NotNull] string scheme,
            [NotNull] Action<OpenIdAuthenticationOptions> configuration) {
            return app.UseMiddleware<OpenIdAuthenticationMiddleware<OpenIdAuthenticationOptions>>(
                new ConfigureOptions<OpenIdAuthenticationOptions>(options => {
                    options.AuthenticationScheme = scheme;
                    options.Caption = scheme;

                    configuration(options);
                }) { Name = scheme });
        }
    }
}
