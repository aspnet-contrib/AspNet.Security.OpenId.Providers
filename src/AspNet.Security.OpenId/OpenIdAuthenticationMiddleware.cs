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
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenId
{
    public class OpenIdAuthenticationMiddleware<TOptions> : AuthenticationMiddleware<TOptions>
        where TOptions : OpenIdAuthenticationOptions, new()
    {
        public OpenIdAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<TOptions> options,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IOptions<SharedAuthenticationOptions> sharedOptions)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                Options.SignInScheme = sharedOptions.Value.SignInScheme;
            }

            if (string.IsNullOrEmpty(Options.SignInScheme))
            {
                throw new ArgumentException("The sign-in scheme cannot be null or empty.", nameof(options));
            }

            if (Options.DataProtectionProvider == null)
            {
                Options.DataProtectionProvider = dataProtectionProvider;
            }

            if (Options.StateDataFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdAuthenticationHandler), Options.AuthenticationScheme);

                Options.StateDataFormat = new PropertiesDataFormat(protector);
            }

            if (Options.HtmlParser == null)
            {
                Options.HtmlParser = new HtmlParser();
            }

            if (Options.HttpClient == null)
            {
                Options.HttpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(30),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                Options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET Core OpenID 2.0 middleware");
            }

            if (Options.ConfigurationManager == null)
            {
                if (Options.Configuration != null)
                {
                    if (string.IsNullOrEmpty(Options.Configuration.AuthenticationEndpoint))
                    {
                        throw new ArgumentException("The authentication endpoint address cannot be null or empty.", nameof(options));
                    }

                    Options.ConfigurationManager = new StaticConfigurationManager<OpenIdAuthenticationConfiguration>(Options.Configuration);
                }

                else
                {
                    if (Options.Authority == null && Options.MetadataAddress == null)
                    {
                        throw new ArgumentException("The authority or an absolute metadata endpoint address must be provided.", nameof(options));
                    }

                    if (Options.MetadataAddress == null)
                    {
                        Options.MetadataAddress = Options.Authority;
                    }

                    if (!Options.MetadataAddress.IsAbsoluteUri)
                    {
                        if (Options.Authority == null || !Options.Authority.IsAbsoluteUri)
                        {
                            throw new ArgumentException("The authority must be provided and must be an absolute URL.", nameof(options));
                        }

                        if (!string.IsNullOrEmpty(Options.Authority.Fragment) || !string.IsNullOrEmpty(Options.Authority.Query))
                        {
                            throw new ArgumentException("The authority cannot contain a fragment or a query string.", nameof(options));
                        }

                        if (!Options.Authority.OriginalString.EndsWith("/"))
                        {
                            Options.Authority = new Uri(Options.Authority.OriginalString + "/", UriKind.Absolute);
                        }

                        Options.MetadataAddress = new Uri(Options.Authority, Options.MetadataAddress);
                    }

                    if (Options.RequireHttpsMetadata && !Options.MetadataAddress.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ArgumentException("The metadata endpoint address must be a HTTPS URL when " +
                                                    "'RequireHttpsMetadata' is not set to 'false'.", nameof(options));
                    }

                    Options.ConfigurationManager = new ConfigurationManager<OpenIdAuthenticationConfiguration>(
                        Options.MetadataAddress?.AbsoluteUri ?? Options.Authority.AbsoluteUri,
                        new OpenIdAuthenticationConfiguration.Retriever(Options.HttpClient, Options.HtmlParser),
                        new HttpDocumentRetriever(Options.HttpClient) { RequireHttps = Options.RequireHttpsMetadata });
                }
            }
        }

        protected override AuthenticationHandler<TOptions> CreateHandler()
        {
            return new OpenIdAuthenticationHandler<TOptions>();
        }
    }
}
