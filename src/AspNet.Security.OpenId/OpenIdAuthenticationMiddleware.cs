/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Net.Http;
using System.Text.Encodings.Web;
using AngleSharp.Parser.Html;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationMiddleware<TOptions> : AuthenticationMiddleware<TOptions>
        where TOptions : OpenIdAuthenticationOptions, new() {
        public OpenIdAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<TOptions> options,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IOptions<SharedAuthenticationOptions> externalOptions)
            : base(next, options, loggerFactory, encoder) {
            if (Options.Authority == null && Options.Endpoint == null) {
                throw new ArgumentException("An authority or an endpoint must be specified.", nameof(options));
            }

            if (string.IsNullOrEmpty(Options.SignInScheme)) {
                Options.SignInScheme = externalOptions.Value.SignInScheme;
            }

            if (Options.StateDataFormat == null) {
                Options.StateDataFormat = new PropertiesDataFormat(
                    dataProtectionProvider.CreateProtector(
                        GetType().FullName, Options.AuthenticationScheme, "v1"));
            }

            if (Options.HtmlParser == null) {
                Options.HtmlParser = new HtmlParser();
            }

            if (Options.HttpClient == null) {
                Options.HttpClient = new HttpClient {
                    Timeout = TimeSpan.FromSeconds(60),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                Options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET OpenID 2.0 middleware");
            }
        }

        protected override AuthenticationHandler<TOptions> CreateHandler() {
            return new OpenIdAuthenticationHandler<TOptions>();
        }
    }
}
