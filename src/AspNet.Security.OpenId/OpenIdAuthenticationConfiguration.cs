/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using AngleSharp.Dom.Html;
using AngleSharp.Parser.Html;
using JetBrains.Annotations;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OpenId
{
    /// <summary>
    /// Represents an OpenID 2.0 configuration.
    /// </summary>
    public class OpenIdAuthenticationConfiguration
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="OpenIdAuthenticationConfiguration"/> class.
        /// </summary>
        public OpenIdAuthenticationConfiguration() { }

        /// <summary>
        /// Gets or sets the authentication endpoint address.
        /// </summary>
        public string AuthenticationEndpoint { get; set; }

        /// <summary>
        /// Represents a configuration retriever able to deserialize
        /// <see cref="OpenIdAuthenticationConfiguration"/> instances.
        /// </summary>
        public class Retriever : IConfigurationRetriever<OpenIdAuthenticationConfiguration>
        {
            /// <summary>
            /// Creates a new instance of the <see cref="Retriever"/> class.
            /// </summary>
            /// <param name="client">The HTTP client used to retrieve the discovery documents.</param>
            /// <param name="parser">The HTML parser used to parse the discovery documents.</param>
            public Retriever([NotNull] HttpClient client, [NotNull] HtmlParser parser)
            {
                if (client == null)
                {
                    throw new ArgumentNullException(nameof(client));
                }

                if (parser == null)
                {
                    throw new ArgumentNullException(nameof(parser));
                }

                HttpClient = client;
                HtmlParser = parser;
            }

            /// <summary>
            /// Gets the HTML parser used to parse the discovery documents.
            /// </summary>
            public HtmlParser HtmlParser { get; }

            /// <summary>
            /// Gets the HTTP client used to retrieve the discovery documents.
            /// </summary>
            public HttpClient HttpClient { get; }

            /// <summary>
            /// Retrieves the OpenID 2.0 configuration from the specified address.
            /// </summary>
            /// <param name="address">The address of the discovery document.</param>
            /// <param name="retriever">The object used to retrieve the discovery document.</param>
            /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
            /// <returns>An <see cref="OpenIdAuthenticationConfiguration"/> instance.</returns>
            public async Task<OpenIdAuthenticationConfiguration> GetConfigurationAsync(
                [NotNull] string address, [NotNull] IDocumentRetriever retriever, CancellationToken cancellationToken)
            {
                if (string.IsNullOrEmpty(address))
                {
                    throw new ArgumentException("The address cannot be null or empty.", nameof(address));
                }

                if (retriever == null)
                {
                    throw new ArgumentNullException(nameof(retriever));
                }

                using (var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
                {
                    // If the final authentication endpoint cannot be found after 30 seconds, abort the discovery operation.
                    cancellationTokenSource.CancelAfter(HttpClient.Timeout < TimeSpan.FromSeconds(30) ?
                                                        HttpClient.Timeout : TimeSpan.FromSeconds(30));

                    do
                    {
                        // application/xrds+xml MUST be the preferred content type to avoid a second round-trip.
                        // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.4)
                        var request = new HttpRequestMessage(HttpMethod.Get, address);
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Xrds));
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Html));
                        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Xhtml));

                        var response = await HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationTokenSource.Token);
                        if (!response.IsSuccessStatusCode)
                        {
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                                "The Yadis discovery failed because an invalid response was received: the identity provider " +
                                "returned returned a {0} response with the following payload: {1} {2}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync()));
                        }

                        // Note: application/xrds+xml is the standard content type but text/xml is frequent.
                        // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
                        var media = response.Content.Headers.ContentType?.MediaType;
                        if (string.Equals(media, OpenIdAuthenticationConstants.Media.Xrds, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(media, OpenIdAuthenticationConstants.Media.Xml, StringComparison.OrdinalIgnoreCase))
                        {
                            using (var stream = await response.Content.ReadAsStreamAsync())
                            using (var reader = XmlReader.Create(stream))
                            {
                                var document = XDocument.Load(reader);

                                var endpoint = (from service in document.Root.Element(XName.Get("XRD", "xri://$xrd*($v*2.0)"))
                                                                             .Descendants(XName.Get("Service", "xri://$xrd*($v*2.0)"))
                                                where service.Descendants(XName.Get("Type", "xri://$xrd*($v*2.0)"))
                                                             .Any(type => type.Value == "http://specs.openid.net/auth/2.0/server")
                                                orderby service.Attribute("priority")?.Value
                                                select service.Element(XName.Get("URI", "xri://$xrd*($v*2.0)"))?.Value).FirstOrDefault();

                                Uri uri;
                                if (!string.IsNullOrEmpty(endpoint) && Uri.TryCreate(endpoint, UriKind.Absolute, out uri))
                                {
                                    return new OpenIdAuthenticationConfiguration
                                    {
                                        AuthenticationEndpoint = uri.AbsoluteUri
                                    };
                                }

                                throw new InvalidOperationException(
                                    "The Yadis discovery failed because the XRDS document returned by the " +
                                    "identity provider was invalid or didn't contain the endpoint address.");
                            }
                        }

                        // Try to extract the XRDS location from the response headers before parsing the body.
                        // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
                        var location = (from header in response.Headers
                                        where string.Equals(header.Key, OpenIdAuthenticationConstants.Headers.XrdsLocation, StringComparison.OrdinalIgnoreCase)
                                        from value in header.Value
                                        select value).FirstOrDefault();

                        if (!string.IsNullOrEmpty(location))
                        {
                            Uri uri;
                            if (!Uri.TryCreate(location, UriKind.Absolute, out uri))
                            {
                                throw new InvalidOperationException(
                                    "The Yadis discovery failed because the X-XRDS-Location " +
                                    "header returned by the identity provider was invalid.");
                            }

                            // Retry the discovery operation, but using the XRDS location extracted from the header.
                            address = uri.AbsoluteUri;

                            continue;
                        }

                        // Only text/html or application/xhtml+xml can be safely parsed.
                        // See http://openid.net/specs/yadis-v1.0.pdf
                        if (string.Equals(media, OpenIdAuthenticationConstants.Media.Html, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(media, OpenIdAuthenticationConstants.Media.Xhtml, StringComparison.OrdinalIgnoreCase))
                        {
                            IHtmlDocument document = null;

                            try
                            {
                                using (var stream = await response.Content.ReadAsStreamAsync())
                                {
                                    document = await HtmlParser.ParseAsync(stream, cancellationTokenSource.Token);
                                }
                            }

                            catch (Exception exception)
                            {
                                throw new InvalidOperationException("An exception occurred while parsing the HTML document.", exception);
                            }

                            var endpoint = (from element in document.Head.GetElementsByTagName(OpenIdAuthenticationConstants.Metadata.Meta)
                                            let attribute = element.Attributes[OpenIdAuthenticationConstants.Metadata.HttpEquiv]
                                            where string.Equals(attribute?.Value, OpenIdAuthenticationConstants.Metadata.XrdsLocation, StringComparison.OrdinalIgnoreCase)
                                            select element.Attributes[OpenIdAuthenticationConstants.Metadata.Content]?.Value).FirstOrDefault();
                            
                            if (!string.IsNullOrEmpty(endpoint))
                            {
                                Uri uri;
                                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out uri))
                                {
                                    throw new InvalidOperationException(
                                        "The Yadis discovery failed because the X-XRDS-Location " +
                                        "metadata returned by the identity provider was invalid.");
                                }

                                // Retry the discovery operation, but using the XRDS
                                // location extracted from the parsed HTML document.
                                address = uri.AbsoluteUri;

                                continue;
                            }
                        }

                        throw new InvalidOperationException("The Yadis discovery failed because the XRDS document location was not found.");
                    }

                    while (!cancellationTokenSource.IsCancellationRequested);
                }

                throw new InvalidOperationException("The OpenID 2.0 configuration cannot be retrieved.");
            }
        }
    }
}
