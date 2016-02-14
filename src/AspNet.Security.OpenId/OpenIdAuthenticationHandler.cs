/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using AngleSharp.Dom.Html;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : OpenIdAuthenticationOptions {
        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync() {
            // Always extract the "state" parameter from the query string.
            var state = Request.Query[OpenIdAuthenticationConstants.Parameters.State];
            if (string.IsNullOrEmpty(state)) {
                return AuthenticateResult.Fail("The authentication response was rejected " +
                                               "because the state parameter was missing.");
            }

            var properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null) {
                return AuthenticateResult.Fail("The authentication response was rejected " +
                                               "because the state parameter was invalid.");
            }

            // Validate the anti-forgery token.
            if (!ValidateCorrelationId(properties)) {
                return AuthenticateResult.Fail("The authentication response was rejected " +
                                               "because the anti-forgery identifier was invalid.");
            }

            IDictionary<string, StringValues> message;

            // OpenID 2.0 responses MUST necessarily be made using either GET or POST.
            // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
            if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                return AuthenticateResult.Fail("The authentication response was rejected because it was made " +
                                               "using an invalid method: make sure to use either GET or POST.");
            }

            if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                message = Request.Query.ToDictionary();
            }

            else {
                // OpenID 2.0 responses MUST include a Content-Type header when using POST.
                // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
                if (string.IsNullOrEmpty(Request.ContentType)) {
                    return AuthenticateResult.Fail("The authentication response was rejected because " +
                                                   "it was missing the mandatory 'Content-Type' header.");
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                    return AuthenticateResult.Fail("The authentication response was rejected because an invalid Content-Type header " +
                                                   "was received: make sure to use 'application/x-www-form-urlencoded'.");
                }

                var form = await Request.ReadFormAsync(Context.RequestAborted);

                message = form.ToDictionary();
            }

            // Ensure that the current request corresponds to an OpenID 2.0 assertion.
            if (!string.Equals(message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                       OpenIdAuthenticationConstants.Parameters.Namespace],
                               OpenIdAuthenticationConstants.Namespaces.OpenId, StringComparison.Ordinal)) {
                return AuthenticateResult.Fail("The authentication response was rejected because it was missing the mandatory " +
                                               "'openid.ns' parameter or because an unsupported version of OpenID was used.");
            }

            // Stop processing the message if the assertion was not positive.
            if (!string.Equals(message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                       OpenIdAuthenticationConstants.Parameters.Mode],
                               OpenIdAuthenticationConstants.Modes.IdRes, StringComparison.Ordinal)) {
                return AuthenticateResult.Fail("The authentication response was rejected because " +
                                               "the identity provider declared it as invalid.");
            }

            // Stop processing the message if the assertion
            // was not validated by the identity provider.
            if (!await VerifyAssertionAsync(message)) {
                return AuthenticateResult.Fail("The authentication response was rejected by the identity provider.");
            }

            // Validate the return_to parameter by comparing it to the address stored in the properties.
            // See http://openid.net/specs/openid-authentication-2_0.html#verify_return_to
            var address = QueryHelpers.AddQueryString(uri: properties.Items[OpenIdAuthenticationConstants.Parameters.ReturnTo],
                                                      name: OpenIdAuthenticationConstants.Parameters.State, value: state);
            if (!string.Equals(message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                       OpenIdAuthenticationConstants.Parameters.ReturnTo], address, StringComparison.Ordinal)) {
                return AuthenticateResult.Fail("The authentication response was rejected because the return_to parameter was invalid.");
            }

            // Create a new dictionary containing the extensions found in the assertion.
            var prefix = OpenIdAuthenticationConstants.Prefixes.OpenId + OpenIdAuthenticationConstants.Prefixes.Namespace;
            var extensions = message.Where(parameter => parameter.Key.StartsWith(prefix, StringComparison.Ordinal))
                                    .ToDictionary(parameter => parameter.Value.FirstOrDefault(),
                                                  parameter => parameter.Key.Substring(prefix.Length));

            // Make sure the OpenID 2.0 assertion contains an identifier.
            var identifier = message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                     OpenIdAuthenticationConstants.Parameters.ClaimedId];
            if (string.IsNullOrEmpty(identifier)) {
                return AuthenticateResult.Fail("The authentication response was rejected because it " +
                                               "was missing the mandatory 'claimed_id' parameter.");
            }

            var identity = new ClaimsIdentity(Options.AuthenticationScheme);

            // Add the claimed identifier to the identity. 
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, identifier, ClaimValueTypes.String, Options.ClaimsIssuer));

            // Create a new dictionary containing the optional attributes extracted from the assertion.
            var attributes = new Dictionary<string, string>(StringComparer.Ordinal);

            // Determine whether attribute exchange has been enabled.
            string alias;
            if (extensions.TryGetValue(OpenIdAuthenticationConstants.Namespaces.Ax, out alias)) {
                foreach (var parameter in message) {
                    // Exclude parameters that don't correspond to the attribute exchange alias.
                    if (!parameter.Key.StartsWith(OpenIdAuthenticationConstants.Prefixes.OpenId + alias +
                                                  OpenIdAuthenticationConstants.Suffixes.Type, StringComparison.Ordinal)) {
                        continue;
                    }

                    // Exclude attributes whose alias is malformed.
                    var name = parameter.Key.Substring((OpenIdAuthenticationConstants.Prefixes.OpenId + alias +
                                                        OpenIdAuthenticationConstants.Suffixes.Type + ".").Length);
                    if (string.IsNullOrEmpty(name)) {
                        continue;
                    }

                    // Exclude attributes whose type is missing.
                    string type = parameter.Value;
                    if (string.IsNullOrEmpty(type)) {
                        continue;
                    }

                    // Exclude attributes whose value is missing.
                    string value = message[OpenIdAuthenticationConstants.Prefixes.OpenId + alias +
                                           OpenIdAuthenticationConstants.Suffixes.Value + $".{name}"];
                    if (string.IsNullOrEmpty(value)) {
                        continue;
                    }

                    attributes.Add(type, value);
                }

                // Add the most common attributes to the identity.
                foreach (var attribute in attributes) {
                    // http://axschema.org/contact/email
                    if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Email, StringComparison.Ordinal)) {
                        identity.AddClaim(new Claim(ClaimTypes.Email, attribute.Value, ClaimValueTypes.Email, Options.ClaimsIssuer));
                    }

                    // http://axschema.org/namePerson
                    else if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Name, StringComparison.Ordinal)) {
                        identity.AddClaim(new Claim(ClaimTypes.Name, attribute.Value, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }

                    // http://axschema.org/namePerson/first
                    else if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Firstname, StringComparison.Ordinal)) {
                        identity.AddClaim(new Claim(ClaimTypes.GivenName, attribute.Value, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }

                    // http://axschema.org/namePerson/last
                    else if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Lastname, StringComparison.Ordinal)) {
                        identity.AddClaim(new Claim(ClaimTypes.Surname, attribute.Value, ClaimValueTypes.String, Options.ClaimsIssuer));
                    }
                }

                // Create a ClaimTypes.Name claim using ClaimTypes.GivenName and ClaimTypes.Surname
                // if the http://axschema.org/namePerson attribute cannot be found in the assertion.
                if (!identity.HasClaim(claim => string.Equals(claim.Type, ClaimTypes.Name, StringComparison.OrdinalIgnoreCase)) &&
                     identity.HasClaim(claim => string.Equals(claim.Type, ClaimTypes.GivenName, StringComparison.OrdinalIgnoreCase)) &&
                     identity.HasClaim(claim => string.Equals(claim.Type, ClaimTypes.Surname, StringComparison.OrdinalIgnoreCase))) {
                    identity.AddClaim(new Claim(ClaimTypes.Name, $"{identity.FindFirst(ClaimTypes.GivenName).Value} " +
                                                                 $"{identity.FindFirst(ClaimTypes.Surname).Value}",
                                                ClaimValueTypes.String, Options.ClaimsIssuer));
                }
            }

            var ticket = await CreateTicketAsync(identity, properties, identifier, attributes);
            if (ticket == null) {
                Logger.LogInformation("The authentication process was skipped because returned a null ticket was returned.");

                return AuthenticateResult.Skip();
            }

            return AuthenticateResult.Success(ticket);
        }

        protected virtual async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity, [NotNull] AuthenticationProperties properties,
            [NotNull] string identifier, [NotNull] IDictionary<string, string> attributes) {
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);

            var context = new OpenIdAuthenticatedContext(Context, Options, ticket);

            // Copy the attributes to the context object.
            foreach (var attribute in attributes) {
                context.Attributes.Add(attribute);
            }

            await Options.Events.Authenticated(context);

            // Note: return the authentication ticket associated
            // with the notification to allow replacing the ticket.
            return context.Ticket;
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context) {
            var properties = new AuthenticationProperties(context.Properties);

            if (Options.Endpoint == null) {
                // Note: altering options during a request is not thread safe but
                // would only result in multiple discovery requests in the worst case.
                Options.Endpoint = await DiscoverEndpointAsync(Options.Authority);
            }

            if (Options.Endpoint == null) {
                Logger.LogError("The user agent cannot be redirected to the identity provider because no " +
                                "endpoint was registered in the options or discovered through Yadis.");

                return true;
            }

            // Determine the realm using the current address
            // if one has not been explicitly provided;
            var realm = Options.Realm;
            if (string.IsNullOrEmpty(realm)) {
                realm = Request.Scheme + "://" + Request.Host + OriginalPathBase;
            }

            // Use the current address as the final location where the user agent
            // will be redirected to if one has not been explicitly provided.
            if (string.IsNullOrEmpty(properties.RedirectUri)) {
                properties.RedirectUri = Request.Scheme + "://" + Request.Host +
                                         OriginalPathBase + Request.Path + Request.QueryString;
            }

            // Store the return_to parameter for later comparison.
            properties.Items[OpenIdAuthenticationConstants.Parameters.ReturnTo] =
                Request.Scheme + "://" + Request.Host +
                OriginalPathBase + Options.CallbackPath;

            // Generate a new anti-forgery token.
            GenerateCorrelationId(properties);

            var state = UrlEncoder.Encode(Options.StateDataFormat.Protect(properties));

            // Create a new dictionary containing the OpenID 2.0 request parameters.
            // See http://openid.net/specs/openid-authentication-2_0.html#requesting_authentication
            var parameters = new Dictionary<string, string> {
                // openid.ns (http://specs.openid.net/auth/2.0)
                [OpenIdAuthenticationConstants.Prefixes.OpenId +
                 OpenIdAuthenticationConstants.Parameters.Namespace] = OpenIdAuthenticationConstants.Namespaces.OpenId,

                // openid.mode (checkid_setup)
                [OpenIdAuthenticationConstants.Prefixes.OpenId +
                 OpenIdAuthenticationConstants.Parameters.Mode] = OpenIdAuthenticationConstants.Modes.CheckIdSetup,

                // openid.claimed_id (http://specs.openid.net/auth/2.0/identifier_select)
                [OpenIdAuthenticationConstants.Prefixes.OpenId +
                 OpenIdAuthenticationConstants.Parameters.ClaimedId] = "http://specs.openid.net/auth/2.0/identifier_select",

                // openid.identity (http://specs.openid.net/auth/2.0/identifier_select)
                [OpenIdAuthenticationConstants.Prefixes.OpenId +
                 OpenIdAuthenticationConstants.Parameters.Identity] = "http://specs.openid.net/auth/2.0/identifier_select",

                // openid.return_to
                [OpenIdAuthenticationConstants.Prefixes.OpenId +
                 OpenIdAuthenticationConstants.Parameters.ReturnTo] = QueryHelpers.AddQueryString(
                     properties.Items[OpenIdAuthenticationConstants.Parameters.ReturnTo], "state", state),

                // openid_realm
                [OpenIdAuthenticationConstants.Prefixes.OpenId + OpenIdAuthenticationConstants.Parameters.Realm] = realm
            };

            if (Options.Attributes.Any()) {
                // openid.ns.ax (http://openid.net/srv/ax/1.0)
                parameters[OpenIdAuthenticationConstants.Prefixes.OpenId +
                           OpenIdAuthenticationConstants.Prefixes.Namespace +
                           OpenIdAuthenticationConstants.Aliases.Ax] = OpenIdAuthenticationConstants.Namespaces.Ax;

                // openid.ax.mode (fetch_request)
                parameters[OpenIdAuthenticationConstants.Prefixes.OpenId +
                           OpenIdAuthenticationConstants.Prefixes.Ax +
                           OpenIdAuthenticationConstants.Parameters.Mode] = OpenIdAuthenticationConstants.Modes.FetchRequest;

                foreach (var attribute in Options.Attributes) {
                    parameters[OpenIdAuthenticationConstants.Prefixes.OpenId +
                               OpenIdAuthenticationConstants.Prefixes.Ax +
                               OpenIdAuthenticationConstants.Prefixes.Type + attribute.Key] = attribute.Value;
                }

                // openid.ax.required
                parameters[OpenIdAuthenticationConstants.Prefixes.OpenId +
                           OpenIdAuthenticationConstants.Prefixes.Ax +
                           OpenIdAuthenticationConstants.Parameters.Required] = string.Join(",", Options.Attributes.Select(attribute => attribute.Key));
            }

            Response.Redirect(await GenerateChallengeUrlAsync(parameters));

            return true;
        }

        protected virtual Task<string> GenerateChallengeUrlAsync([NotNull] IDictionary<string, string> parameters) {
            return Task.FromResult(QueryHelpers.AddQueryString(Options.Endpoint.AbsoluteUri, parameters));
        }

        protected virtual async Task<Uri> DiscoverEndpointAsync([NotNull] Uri address) {
            // application/xrds+xml MUST be the preferred content type to avoid a second round-trip.
            // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.4)
            var request = new HttpRequestMessage(HttpMethod.Get, address);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Xrds));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Html));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Xhtml));

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogWarning("The Yadis discovery failed because an invalid response was received: the identity provider " +
                                  "returned returned a {Status} response with the following payload: {Headers} {Body}.",
                                  /* Status: */ response.StatusCode,
                                  /* Headers: */ response.Headers.ToString(),
                                  /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            // Note: application/xrds+xml is the standard content type but text/xml is frequent.
            // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
            if (string.Equals(response.Content.Headers.ContentType?.MediaType,
                              OpenIdAuthenticationConstants.Media.Xrds, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(response.Content.Headers.ContentType?.MediaType,
                              OpenIdAuthenticationConstants.Media.Xml, StringComparison.OrdinalIgnoreCase)) {
                using (var stream = await response.Content.ReadAsStreamAsync())
                using (var reader = XmlReader.Create(stream, new XmlReaderSettings { Async = true })) {
                    var document = XDocument.Load(reader);

                    var endpoint = (from service in document.Root.Element(XName.Get("XRD", "xri://$xrd*($v*2.0)"))
                                                                 .Descendants(XName.Get("Service", "xri://$xrd*($v*2.0)"))
                                    where service.Descendants(XName.Get("Type", "xri://$xrd*($v*2.0)"))
                                                 .Any(type => type.Value == "http://specs.openid.net/auth/2.0/server")
                                    orderby service.Attribute("priority")?.Value
                                    select service.Element(XName.Get("URI", "xri://$xrd*($v*2.0)"))?.Value).FirstOrDefault();

                    if (!string.IsNullOrEmpty(endpoint) && Uri.TryCreate(endpoint, UriKind.Absolute, out address)) {
                        return address;
                    }

                    Logger.LogWarning("The Yadis discovery failed because the XRDS document returned by the " +
                                      "identity provider was invalid or didn't contain the endpoint address.");

                    return null;
                }
            }

            // Try to extract the XRDS location from the response headers before parsing the body.
            // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
            var location = (from header in response.Headers
                            where string.Equals(header.Key, OpenIdAuthenticationConstants.Headers.XrdsLocation, StringComparison.OrdinalIgnoreCase)
                            from value in header.Value
                            select value).FirstOrDefault();

            if (!string.IsNullOrEmpty(location)) {
                if (!Uri.TryCreate(location, UriKind.Absolute, out address) &&
                    !Uri.TryCreate(Options.Authority, location, out address)) {
                    Logger.LogWarning("The Yadis discovery failed because the X-XRDS-Location " +
                                      "header returned by the identity provider was invalid.");

                    return null;
                }

                return await DiscoverEndpointAsync(address);
            }

            // Only text/html or application/xhtml+xml can be safely parsed.
            // See http://openid.net/specs/yadis-v1.0.pdf
            if (string.Equals(response.Content.Headers.ContentType?.MediaType,
                              OpenIdAuthenticationConstants.Media.Html, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(response.Content.Headers.ContentType?.MediaType,
                              OpenIdAuthenticationConstants.Media.Xhtml, StringComparison.OrdinalIgnoreCase)) {
                IHtmlDocument document = null;

                try {
                    document = Options.HtmlParser.Parse(await response.Content.ReadAsStreamAsync());
                    Debug.Assert(document != null);
                }

                catch (Exception exception) {
                    Logger.LogWarning("An exception occurred when parsing the HTML document.", exception);

                    return null;
                }

                var endpoint = (from element in document.Head.GetElementsByTagName(OpenIdAuthenticationConstants.Metadata.Meta)
                                let attribute = element.Attributes[OpenIdAuthenticationConstants.Metadata.HttpEquiv]
                                where string.Equals(attribute?.Value, OpenIdAuthenticationConstants.Metadata.XrdsLocation, StringComparison.OrdinalIgnoreCase)
                                select element.Attributes[OpenIdAuthenticationConstants.Metadata.Content]?.Value).FirstOrDefault();

                if (!string.IsNullOrEmpty(endpoint) && Uri.TryCreate(endpoint, UriKind.Absolute, out address)) {
                    return address;
                }
            }

            Logger.LogWarning("The Yadis discovery failed because the XRDS document location was not found.");

            return null;
        }

        protected virtual async Task<bool> VerifyAssertionAsync([NotNull] IDictionary<string, StringValues> message) {
            // Create a new dictionary to store the parameters sent to the identity provider.
            // Note: using a dictionary is safe as OpenID 2.0 parameters are supposed to be unique.
            // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
            var payload = new Dictionary<string, string> {
                [OpenIdAuthenticationConstants.Prefixes.OpenId +
                 OpenIdAuthenticationConstants.Parameters.Mode] = OpenIdAuthenticationConstants.Modes.CheckAuthentication
            };

            // Copy the parameters extracted from the assertion.
            foreach (var parameter in message) {
                if (string.Equals(parameter.Key, OpenIdAuthenticationConstants.Prefixes.OpenId +
                                                 OpenIdAuthenticationConstants.Parameters.Mode, StringComparison.Ordinal)) {
                    continue;
                }

                // Note: the "state" parameter is ignored as it is not part of the
                // OpenID message but directly flowed in the return_to parameter.
                if (string.Equals(parameter.Key, OpenIdAuthenticationConstants.Parameters.State, StringComparison.Ordinal)) {
                    continue;
                }

                payload.Add(parameter.Key, parameter.Value.FirstOrDefault());
            }

            // Create a new check_authentication request to verify the assertion.
            var request = new HttpRequestMessage(HttpMethod.Post, Options.Endpoint);
            request.Content = new FormUrlEncodedContent(payload);

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogWarning("The authentication failed because an invalid check_authentication response was received: " +
                                  "the identity provider returned a {Status} response with the following payload: {Headers} {Body}.",
                                  /* Status: */ response.StatusCode,
                                  /* Headers: */ response.Headers.ToString(),
                                  /* Body: */ await response.Content.ReadAsStringAsync());

                return false;
            }

            using (var stream = await response.Content.ReadAsStreamAsync())
            using (var reader = new StreamReader(stream)) {
                // Create a new dictionary containing the parameters extracted from the response body.
                var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

                // Note: the response is encoded using the 'Key-Value Form Encoding'.
                // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
                for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync()) {
                    var parameter = line.Split(':');
                    if (parameter.Length != 2) {
                        continue;
                    }

                    parameters.Add(parameter[0], parameter[1]);
                }

                // Stop processing the assertion if the mandatory is_valid
                // parameter was missing from the response body.
                if (!parameters.ContainsKey(OpenIdAuthenticationConstants.Parameters.IsValid)) {
                    Logger.LogWarning("The authentication response was rejected because the identity provider " +
                                      "returned an invalid check_authentication response.");

                    return false;
                }

                // Stop processing the assertion if the authentication server declared it as invalid.
                if (!string.Equals(parameters[OpenIdAuthenticationConstants.Parameters.IsValid], "true", StringComparison.Ordinal)) {
                    Logger.LogWarning("The authentication response was rejected because the identity provider " +
                                      "declared the security assertion as invalid.");

                    return false;
                }
            }

            return true;
        }
    }
}
