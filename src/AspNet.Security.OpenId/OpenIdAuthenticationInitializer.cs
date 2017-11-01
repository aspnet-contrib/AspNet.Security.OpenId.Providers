/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Net.Http;
using AngleSharp.Parser.Html;
using AspNet.Security.OpenId;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration used by
    /// the OpenID 2.0 generic handler is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OpenIdAuthenticationInitializer<TOptions, THandler> : IPostConfigureOptions<TOptions>
        where TOptions : OpenIdAuthenticationOptions, new()
        where THandler : OpenIdAuthenticationHandler<TOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OpenIdAuthenticationInitializer{TOptions, THandler}"/> class.
        /// </summary>
        public OpenIdAuthenticationInitializer([NotNull] IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        /// <summary>
        /// Populates the default OpenID 2.0 handler options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] TOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.StateDataFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    nameof(OpenIdAuthenticationHandler), name);

                options.StateDataFormat = new PropertiesDataFormat(protector);
            }

            if (options.HtmlParser == null)
            {
                options.HtmlParser = new HtmlParser();
            }

            if (options.HttpClient == null)
            {
                options.HttpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(30),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET Core OpenID 2.0 middleware");
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    if (string.IsNullOrEmpty(options.Configuration.AuthenticationEndpoint))
                    {
                        throw new ArgumentException("The authentication endpoint address cannot be null or empty.", nameof(options));
                    }

                    options.ConfigurationManager = new StaticConfigurationManager<OpenIdAuthenticationConfiguration>(options.Configuration);
                }

                else
                {
                    if (options.Authority == null && options.MetadataAddress == null)
                    {
                        throw new ArgumentException("The authority or an absolute metadata endpoint address must be provided.", nameof(options));
                    }

                    if (options.MetadataAddress == null)
                    {
                        options.MetadataAddress = options.Authority;
                    }

                    if (!options.MetadataAddress.IsAbsoluteUri)
                    {
                        if (options.Authority == null || !options.Authority.IsAbsoluteUri)
                        {
                            throw new ArgumentException("The authority must be provided and must be an absolute URL.", nameof(options));
                        }

                        if (!string.IsNullOrEmpty(options.Authority.Fragment) || !string.IsNullOrEmpty(options.Authority.Query))
                        {
                            throw new ArgumentException("The authority cannot contain a fragment or a query string.", nameof(options));
                        }

                        if (!options.Authority.OriginalString.EndsWith("/"))
                        {
                            options.Authority = new Uri(options.Authority.OriginalString + "/", UriKind.Absolute);
                        }

                        options.MetadataAddress = new Uri(options.Authority, options.MetadataAddress);
                    }

                    if (options.RequireHttpsMetadata && !options.MetadataAddress.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ArgumentException("The metadata endpoint address must be a HTTPS URL when " +
                                                    "'RequireHttpsMetadata' is not set to 'false'.", nameof(options));
                    }

                    options.ConfigurationManager = new ConfigurationManager<OpenIdAuthenticationConfiguration>(
                        options.MetadataAddress?.AbsoluteUri ?? options.Authority.AbsoluteUri,
                        new OpenIdAuthenticationConfiguration.Retriever(options.HttpClient, options.HtmlParser),
                        new HttpDocumentRetriever(options.HttpClient) { RequireHttps = options.RequireHttpsMetadata });
                }
            }
        }
    }
}