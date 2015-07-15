﻿using System;
using System.Net.Http;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.DataHandler;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.Logging;
using Microsoft.Framework.OptionsModel;
using Microsoft.Framework.WebEncoders;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationMiddleware<TOptions> : AuthenticationMiddleware<TOptions>
        where TOptions : OpenIdAuthenticationOptions, new() {
        public OpenIdAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] IUrlEncoder encoder,
            [NotNull] IOptions<ExternalAuthenticationOptions> externalOptions,
            [NotNull] IOptions<TOptions> options,
            ConfigureOptions<TOptions> configureOptions = null)
            : base(next, options, loggerFactory, encoder, configureOptions) {
            if (string.IsNullOrEmpty(Options.SignInScheme)) {
                Options.SignInScheme = externalOptions.Options.SignInScheme;
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
