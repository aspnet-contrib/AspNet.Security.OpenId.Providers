/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Globalization;
using System.Net.Http.Headers;
using System.Xml;
using System.Xml.Linq;
using AngleSharp.Html.Parser;
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
        public string? AuthenticationEndpoint { get; set; }

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
                HttpClient = client ?? throw new ArgumentNullException(nameof(client));
                HtmlParser = parser ?? throw new ArgumentNullException(nameof(parser));
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
            /// Gets the maximal number of roundtrips that are allowed
            /// before the discovery process is automatically aborted.
            /// By default, this property is set to <c>5</c>.
            /// </summary>
            public int MaximumRedirections { get; set; } = 5;

            /// <summary>
            /// Retrieves the OpenID 2.0 configuration from the specified address.
            /// </summary>
            /// <param name="address">The address of the discovery document.</param>
            /// <param name="retriever">The object used to retrieve the discovery document.</param>
            /// <param name="cancellationToken">The <see cref="CancellationToken"/> that can be used to abort the operation.</param>
            /// <returns>An <see cref="OpenIdAuthenticationConfiguration"/> instance.</returns>
            public Task<OpenIdAuthenticationConfiguration> GetConfigurationAsync(
                [NotNull] string address, [NotNull] IDocumentRetriever retriever, CancellationToken cancellationToken)
            {
                if (retriever == null)
                {
                    throw new ArgumentNullException(nameof(retriever));
                }

                if (string.IsNullOrEmpty(address))
                {
                    throw new ArgumentException("The address cannot be null or empty.", nameof(address));
                }

                if (!Uri.TryCreate(address, UriKind.Absolute, out Uri? uri))
                {
                    throw new ArgumentException("The address must be an absolute URI.", nameof(address));
                }

                if (MaximumRedirections < 1)
                {
                    throw new InvalidOperationException("The maximal number of redirections must be a non-zero positive number.");
                }

                return DiscoverConfigurationAsync(uri, cancellationToken);
            }

            private async Task<OpenIdAuthenticationConfiguration> DiscoverConfigurationAsync(
                [NotNull] Uri address, CancellationToken cancellationToken)
            {
                Debug.Assert(address != null, "The address shouldn't be null or empty.");

                for (var index = 0; index < MaximumRedirections; index++)
                {
                    // Abort the operation if cancellation was requested.
                    cancellationToken.ThrowIfCancellationRequested();

                    // application/xrds+xml MUST be the preferred content type to avoid a second round-trip.
                    // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.4)
                    using var request = new HttpRequestMessage(HttpMethod.Get, address);
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Xrds));
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Html));
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Xhtml));

                    var response = await HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture,
                            "The Yadis discovery failed because an invalid response was received: the identity provider " +
                            "returned returned a {0} response with the following payload: {1} {2}.",
                            /* Status: */ response.StatusCode,
                            /* Headers: */ response.Headers.ToString(),
                            /* Body: */ await response.Content.ReadAsStringAsync(cancellationToken)));
                    }

                    // Note: application/xrds+xml is the standard content type but text/xml is frequent.
                    // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
                    var media = response.Content.Headers.ContentType?.MediaType;
                    if (string.Equals(media, OpenIdAuthenticationConstants.Media.Xrds, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(media, OpenIdAuthenticationConstants.Media.Xml, StringComparison.OrdinalIgnoreCase))
                    {
                        var endpoint = await ProcessXrdsDocumentAsync(response, cancellationToken);
                        if (endpoint == null)
                        {
                            throw new InvalidOperationException(
                                "The Yadis discovery failed because the XRDS document returned by the " +
                                "identity provider didn't contain the authentication endpoint address.");
                        }

                        return new OpenIdAuthenticationConfiguration
                        {
                            AuthenticationEndpoint = endpoint.AbsoluteUri
                        };
                    }

                    // Try to extract the XRDS location from the response headers before parsing the body.
                    // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
                    if (response.Headers.Contains(OpenIdAuthenticationConstants.Headers.XrdsLocation))
                    {
                        var location = ProcessGenericDocument(response);
                        if (location != null)
                        {
                            // Retry the discovery operation, but using the
                            // XRDS location extracted from the header.
                            address = location;

                            continue;
                        }
                    }

                    // Only text/html or application/xhtml+xml can be safely parsed.
                    // See http://openid.net/specs/yadis-v1.0.pdf
                    if (string.Equals(media, OpenIdAuthenticationConstants.Media.Html, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(media, OpenIdAuthenticationConstants.Media.Xhtml, StringComparison.OrdinalIgnoreCase))
                    {
                        var location = await ProcessHtmlDocumentAsync(response, cancellationToken);
                        if (location != null)
                        {
                            // Retry the discovery operation, but using the
                            // XRDS location extracted from the HTML document.
                            address = location;

                            continue;
                        }
                    }
                }

                throw new InvalidOperationException("The Yadis discovery failed because the XRDS document location was not found.");
            }

            private static async Task<Uri?> ProcessXrdsDocumentAsync(
                [NotNull] HttpResponseMessage response, CancellationToken cancellationToken)
            {
                Debug.Assert(response != null, "The HTTP response shouldn't be null.");

                // Abort the operation if cancellation was requested.
                cancellationToken.ThrowIfCancellationRequested();

                using (var stream = await response.Content.ReadAsStreamAsync(cancellationToken))
                using (var reader = XmlReader.Create(stream))
                {
                    var document = XDocument.Load(reader);

                    var endpoint = (from service in document.Root!.Element(XName.Get("XRD", "xri://$xrd*($v*2.0)"))!
                                                                 .Descendants(XName.Get("Service", "xri://$xrd*($v*2.0)"))
                                    where service.Descendants(XName.Get("Type", "xri://$xrd*($v*2.0)"))
                                                 .Any(type => type.Value == "http://specs.openid.net/auth/2.0/server")
                                    orderby service.Attribute("priority"!)?.Value
                                    select service.Element(XName.Get("URI", "xri://$xrd*($v*2.0)"))?.Value).FirstOrDefault();

                    if (string.IsNullOrEmpty(endpoint))
                    {
                        return null;
                    }

                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri))
                    {
                        throw new InvalidOperationException(
                            "The Yadis discovery failed because the XRDS document " +
                            "returned by the identity provider was invalid.");
                    }

                    return uri;
                }
            }

            private static Uri? ProcessGenericDocument(HttpResponseMessage response)
            {
                var endpoint = (from header in response.Headers
                                where string.Equals(header.Key, OpenIdAuthenticationConstants.Headers.XrdsLocation, StringComparison.OrdinalIgnoreCase)
                                from value in header.Value
                                select value).FirstOrDefault();

                if (string.IsNullOrEmpty(endpoint))
                {
                    return null;
                }

                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri))
                {
                    throw new InvalidOperationException(
                        "The Yadis discovery failed because the X-XRDS-Location " +
                        "header returned by the identity provider was invalid.");
                }

                return uri;
            }

            private async Task<Uri?> ProcessHtmlDocumentAsync(
                [NotNull] HttpResponseMessage response, CancellationToken cancellationToken)
            {
                Debug.Assert(response != null, "The HTTP response shouldn't be null.");

                // Abort the operation if cancellation was requested.
                cancellationToken.ThrowIfCancellationRequested();

                using (var stream = await response.Content.ReadAsStreamAsync(cancellationToken))
                using (var document = await HtmlParser.ParseDocumentAsync(stream, cancellationToken))
                {
                    var endpoint = (from element in document.Head.GetElementsByTagName(OpenIdAuthenticationConstants.Metadata.Meta)
                                    let attribute = element.Attributes[OpenIdAuthenticationConstants.Metadata.HttpEquiv]
                                    where string.Equals(attribute?.Value, OpenIdAuthenticationConstants.Metadata.XrdsLocation, StringComparison.OrdinalIgnoreCase)
                                    select element.Attributes[OpenIdAuthenticationConstants.Metadata.Content]?.Value).FirstOrDefault();

                    if (string.IsNullOrEmpty(endpoint))
                    {
                        return null;
                    }

                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri))
                    {
                        throw new InvalidOperationException(
                            "The Yadis discovery failed because the X-XRDS-Location " +
                            "metadata returned by the identity provider was invalid.");
                    }

                    return uri;
                }
            }
        }
    }
}
