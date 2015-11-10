/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.Http.Features.Authentication;
using Microsoft.AspNet.WebUtilities;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNet.Builder;

#if DNX451
using CsQuery;
#endif

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationHandler<TOptions> : RemoteAuthenticationHandler<TOptions> where TOptions : OpenIdAuthenticationOptions {
        protected override async Task<AuthenticateResult> HandleRemoteAuthenticateAsync() {
            try {
                // Always extract the "state" parameter from the query string.
                var state = Request.Query[OpenIdAuthenticationConstants.Parameters.State];
                if (string.IsNullOrEmpty(state)) {
                    Logger.LogWarning("The authentication response was rejected " +
                                      "because the state parameter was missing.");

                    return AuthenticateResult.Failed("The mandatory state parameter was missing.");
                }

                var properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null) {
                    Logger.LogWarning("The authentication response was rejected " +
                                      "because the state parameter was invalid.");

                    return AuthenticateResult.Failed("The state parameter was invalid.");
                }

                // Validate the anti-forgery token.
                if (!ValidateCorrelationId(properties)) {
                    Logger.LogWarning("The authentication response was rejected " +
                                      "because the anti-forgery identifier was invalid.");

                    return AuthenticateResult.Failed("The anti-forgery identifier was invalid.");
                }

                IDictionary<string, StringValues> message;

                // OpenID 2.0 responses MUST necessarily be made using either GET or POST.
                // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
                if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase)) {
                    Logger.LogWarning("The authentication response was rejected because it was made " +
                                      "using an invalid method: make sure to use either GET or POST.");

                    return AuthenticateResult.Failed("The authentication response used an invalid method.");
                }

                if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase)) {
                    message = Request.Query.ToDictionary();
                }

                else {
                    // OpenID 2.0 responses MUST include a Content-Type header when using POST.
                    // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
                    if (string.IsNullOrEmpty(Request.ContentType)) {
                        Logger.LogWarning("The authentication response was rejected because " +
                                          "it was missing the mandatory 'Content-Type' header.");

                        return AuthenticateResult.Failed("The authentication response used an invalid content type.");
                    }

                    // May have media/type; charset=utf-8, allow partial match.
                    if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase)) {
                        Logger.LogWarning("The authentication response was rejected because an invalid Content-Type header " +
                                          "was received: make sure to use 'application/x-www-form-urlencoded'.");

                        return AuthenticateResult.Failed("The authentication response used an unsupported content type.");
                    }

                    var form = await Request.ReadFormAsync(Context.RequestAborted);

                    message = form.ToDictionary();
                }

                // Ensure that the current request corresponds to an OpenID 2.0 assertion.
                if (!string.Equals(message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                           OpenIdAuthenticationConstants.Parameters.Namespace],
                                   OpenIdAuthenticationConstants.Namespaces.OpenId, StringComparison.Ordinal)) {
                    Logger.LogWarning("The authentication response was rejected because it was missing the mandatory " +
                                      "'openid.ns' parameter or because an unsupported version of OpenID was used.");

                    return AuthenticateResult.Failed("The authentication response used an unsupported OpenID version.");
                }

                // Stop processing the message if the assertion was not positive.
                if (!string.Equals(message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                           OpenIdAuthenticationConstants.Parameters.Mode],
                                   OpenIdAuthenticationConstants.Modes.IdRes, StringComparison.Ordinal)) {
                    Logger.LogWarning("The authentication response was rejected because " +
                                      "the identity provider declared it as invalid.");

                    return AuthenticateResult.Failed("The authentication response was rejected by the identity provider.");
                }

                // Stop processing the message if the assertion
                // was not validated by the identity provider.
                if (!await VerifyAssertionAsync(message)) {
                    return AuthenticateResult.Failed("The authentication response was rejected by the identity provider.");
                }

                // Validate the return_to parameter by comparing it to the address stored in the properties.
                // See http://openid.net/specs/openid-authentication-2_0.html#verify_return_to
                var address = QueryHelpers.AddQueryString(uri: properties.Items[OpenIdAuthenticationConstants.Parameters.ReturnTo],
                                                          name: OpenIdAuthenticationConstants.Parameters.State, value: state);
                if (!string.Equals(message[OpenIdAuthenticationConstants.Prefixes.OpenId +
                                           OpenIdAuthenticationConstants.Parameters.ReturnTo], address, StringComparison.Ordinal)) {
                    Logger.LogWarning("The authentication response was rejected because the return_to parameter was invalid.");

                    return AuthenticateResult.Failed("The authentication response was rejected due to an invalid return_to parameter.");
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
                    Logger.LogWarning("The authentication response was rejected because it " +
                                      "was missing the mandatory 'claimed_id' parameter.");

                    return AuthenticateResult.Failed("The authentication response was rejected due to an invalid 'claimed_id'.");
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
                        var name = parameter.Key.Substring($"openid.{alias}.type.".Length);
                        if (string.IsNullOrEmpty(name)) {
                            continue;
                        }

                        // Exclude attributes whose type is missing.
                        string type = parameter.Value;
                        if (string.IsNullOrEmpty(type)) {
                            continue;
                        }

                        // Exclude attributes whose value is missing.
                        string value = message[$"openid.{alias}.value.{name}"];
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
                    Logger.LogWarning("The authentication process cannot complete " +
                                      "because CreateTicketAsync returned a null ticket.");

                    return null;
                }

                return AuthenticateResult.Success(ticket);
            }

            catch (Exception exception) {
                Logger.LogError("Authentication failed due to an unknown exception: {0}.", exception);

                return AuthenticateResult.Failed(exception);
            }
        }

        protected virtual async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity, [NotNull] AuthenticationProperties properties,
            [NotNull] string identifier, [NotNull] IDictionary<string, string> attributes) {
            var context = new OpenIdAuthenticatedContext(Context, Options) {
                Attributes = attributes.ToImmutableDictionary(),
                Principal = new ClaimsPrincipal(identity),
                Properties = properties,
                Identifier = identifier
            };

            await Options.Events.Authenticated(context);

            if (context.Principal?.Identity == null) {
                return null;
            }

            return new AuthenticationTicket(context.Principal, context.Properties, Options.AuthenticationScheme);
        }

        protected override async Task<bool> HandleUnauthorizedAsync(ChallengeContext context) {
            var properties = new AuthenticationProperties(context.Properties);

            if (string.IsNullOrEmpty(Options.Endpoint)) {
                // Note: altering options during a request is not thread safe but
                // would only result in multiple discovery requests in the worst case.
                Options.Endpoint = await DiscoverEndpointAsync(Options.Authority);
            }

            if (string.IsNullOrEmpty(Options.Endpoint)) {
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
            return Task.FromResult(QueryHelpers.AddQueryString(Options.Endpoint, parameters));
        }

        protected virtual async Task<string> DiscoverEndpointAsync([NotNull] Uri address) {
            // application/xrds+xml MUST be the preferred content type to avoid a second round-trip.
            // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.4)
            var request = new HttpRequestMessage(HttpMethod.Get, address);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xrds+xml"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/html"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/xhtml+xml"));

            var response = await Options.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogWarning("The Yadis discovery failed because an invalid response was returned by the identity provider.");

                return null;
            }

            // Note: application/xrds+xml is the standard content type but text/xml is frequent.
            // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
            if (string.Equals(response.Content.Headers.ContentType?.MediaType, "application/xrds+xml") ||
                string.Equals(response.Content.Headers.ContentType?.MediaType, "text/xml")) {
                using (var stream = await response.Content.ReadAsStreamAsync())
                using (var reader = XmlReader.Create(stream, new XmlReaderSettings { Async = true })) {
                    var document = XDocument.Load(reader);

                    var endpoint = (from service in document.Root.Element(XName.Get("XRD", "xri://$xrd*($v*2.0)"))
                                                                 .Descendants(XName.Get("Service", "xri://$xrd*($v*2.0)"))
                                    where service.Descendants(XName.Get("Type", "xri://$xrd*($v*2.0)"))
                                                 .Any(type => type.Value == "http://specs.openid.net/auth/2.0/server")
                                    orderby service.Attribute("priority")?.Value
                                    select service.Element(XName.Get("URI", "xri://$xrd*($v*2.0)"))?.Value).FirstOrDefault();

                    if (!string.IsNullOrEmpty(endpoint)) {
                        return endpoint;
                    }

                    Logger.LogWarning("The Yadis discovery failed because the XRDS document returned by the " +
                                      "identity provider was invalid or didn't contain the endpoint address.");

                    return null;
                }
            }

            // Try to extract the XRDS location from the response headers before parsing the body.
            // See http://openid.net/specs/yadis-v1.0.pdf (chapter 6.2.6)
            var location = (from header in response.Headers
                            where string.Equals(header.Key, "X-XRDS-Location", StringComparison.OrdinalIgnoreCase)
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

#if DNX451
            // Only text/html or application/xhtml+xml can be safely parsed.
            // See http://openid.net/specs/yadis-v1.0.pdf
            if (string.Equals(response.Content.Headers.ContentType?.MediaType, "text/html") ||
                string.Equals(response.Content.Headers.ContentType?.MediaType, "application/xhtml+xml")) {
                var document = CQ.CreateDocument(await response.Content.ReadAsStringAsync());

                // Use LINQ instead of a CSS selector
                // to execute a case-insensitive search.
                var endpoint = (from meta in document.Find("meta")
                                where string.Equals(meta.Attributes["http-equiv"], "X-XRDS-Location", StringComparison.OrdinalIgnoreCase)
                                select meta.Attributes["content"]).FirstOrDefault();

                if (!string.IsNullOrEmpty(endpoint)) {
                    return endpoint;
                }
            }
#endif

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

            var response = await Options.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode) {
                Logger.LogWarning("The authentication response was rejected because the identity provider " +
                                  "returned an invalid check_authentication response.");

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

        protected void GenerateCorrelationId([NotNull] AuthenticationProperties properties) {
            var correlationKey = ".AspNet.Correlation." + Options.AuthenticationScheme;

            var nonceBytes = new byte[32];
            Options.RandomNumberGenerator.GetBytes(nonceBytes);
            var correlationId = Base64UrlTextEncoder.Encode(nonceBytes);

            properties.Items[correlationKey] = correlationId;

            Response.Cookies.Append(correlationKey, correlationId, new CookieOptions {
                HttpOnly = true,
                Secure = Request.IsHttps
            });
        }

        protected bool ValidateCorrelationId([NotNull] AuthenticationProperties properties) {
            var correlationKey = ".AspNet.Correlation." + Options.AuthenticationScheme;

            var correlationCookie = Request.Cookies[correlationKey];
            if (string.IsNullOrWhiteSpace(correlationCookie)) {
                Logger.LogWarning("{0} cookie not found.", correlationKey);

                return false;
            }

            Response.Cookies.Delete(correlationKey, new CookieOptions {
                HttpOnly = true,
                Secure = Request.IsHttps
            });

            string correlationExtra;
            if (!properties.Items.TryGetValue(correlationKey, out correlationExtra)) {
                Logger.LogWarning("{0} state property not found.", correlationKey);

                return false;
            }

            properties.Items.Remove(correlationKey);

            if (!string.Equals(correlationCookie, correlationExtra, StringComparison.Ordinal)) {
                Logger.LogWarning("{0} correlation cookie and state property mismatch.", correlationKey);

                return false;
            }

            return true;
        }
    }
}
