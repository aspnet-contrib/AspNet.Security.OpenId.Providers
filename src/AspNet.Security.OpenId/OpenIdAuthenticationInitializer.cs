using System;
using System.Net.Http;
using System.Text;
using AngleSharp.Parser.Html;
using AspNet.Security.OpenId;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;

namespace Microsoft.Extensions.DependencyInjection
{
    public class OpenIdAuthenticationInitializer<TOptions, THandler> : IPostConfigureOptions<TOptions>
        where TOptions : OpenIdAuthenticationOptions, new()
        where THandler : OpenIdAuthenticationHandler<TOptions>
    {
        private readonly IDataProtectionProvider _dataProtectionProvider;

        public OpenIdAuthenticationInitializer(IDataProtectionProvider dataProtectionProvider)
        {
            _dataProtectionProvider = dataProtectionProvider;
        }

        /// <summary>
        /// Invoked to post configure a TOptions instance.
        /// </summary>
        /// <param name="name">The name of the options instance being configured.</param>
        /// <param name="options">The options instance to configure.</param>
        public void PostConfigure(string name, TOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? _dataProtectionProvider;

            if (options.StateDataFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    GetType().FullName, name, "v1");

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