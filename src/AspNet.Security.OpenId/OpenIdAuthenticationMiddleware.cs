/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Net.Http;
using System.Text.Encodings.Web;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationMiddleware<TOptions> : AuthenticationMiddleware<TOptions>
        where TOptions : OpenIdAuthenticationOptions, new() {
        public OpenIdAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] TOptions options,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IOptions<SharedAuthenticationOptions> externalOptions)
            : base(next, options, loggerFactory, encoder) {
            if (string.IsNullOrEmpty(Options.SignInScheme)) {
                Options.SignInScheme = externalOptions.Value.SignInScheme;
            }

            if (Options.StateDataFormat == null) {
                Options.StateDataFormat = new PropertiesDataFormat(
                    dataProtectionProvider.CreateProtector(
                        GetType().FullName, Options.AuthenticationScheme, "v1"));
            }

            if (Options.Client == null) {
                Options.Client = new HttpClient {
                    Timeout = TimeSpan.FromSeconds(60),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                Options.Client.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET OpenID 2.0 middleware");
            }
        }

        protected override AuthenticationHandler<TOptions> CreateHandler() {
            return new OpenIdAuthenticationHandler<TOptions>();
        }
    }
}
