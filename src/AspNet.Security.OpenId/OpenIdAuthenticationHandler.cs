/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using AspNet.Security.OpenId.Events;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenId;

public class OpenIdAuthenticationHandler(
    [NotNull] IOptionsMonitor<OpenIdAuthenticationOptions> options,
    [NotNull] ILoggerFactory logger,
    [NotNull] UrlEncoder encoder) : OpenIdAuthenticationHandler<OpenIdAuthenticationOptions>(options, logger, encoder)
{
}

public partial class OpenIdAuthenticationHandler<TOptions> : RemoteAuthenticationHandler<TOptions>
    where TOptions : OpenIdAuthenticationOptions, new()
{
    public OpenIdAuthenticationHandler(
        [NotNull] IOptionsMonitor<TOptions> options,
        [NotNull] ILoggerFactory logger,
        [NotNull] UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected new OpenIdAuthenticationEvents Events
    {
        get { return (OpenIdAuthenticationEvents)base.Events; }
        set { base.Events = value; }
    }

    protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
    {
        // OpenID 2.0 responses MUST necessarily be made using either GET or POST.
        // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
        if (!string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            return HandleRequestResult.Fail("The authentication response was rejected because it was made " +
                                            "using an invalid method: make sure to use either GET or POST.");
        }

        // Always extract the "state" parameter from the query string.
        var state = Request.Query[OpenIdAuthenticationConstants.Parameters.State];
        if (string.IsNullOrEmpty(state))
        {
            return HandleRequestResult.Fail("The authentication response was rejected " +
                                            "because the state parameter was missing.");
        }

        var properties = Options.StateDataFormat!.Unprotect(state);
        if (properties == null)
        {
            return HandleRequestResult.Fail("The authentication response was rejected " +
                                            "because the state parameter was invalid.");
        }

        // Validate the anti-forgery token.
        if (!ValidateCorrelationId(properties))
        {
            return HandleRequestResult.Fail("The authentication response was rejected " +
                                            "because the anti-forgery token was invalid.");
        }

        OpenIdAuthenticationMessage message;

        if (string.Equals(Request.Method, "GET", StringComparison.OrdinalIgnoreCase))
        {
            message = new OpenIdAuthenticationMessage(Request.Query);
        }

        else
        {
            // OpenID 2.0 responses MUST include a Content-Type header when using POST.
            // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
            if (string.IsNullOrEmpty(Request.ContentType))
            {
                return HandleRequestResult.Fail("The authentication response was rejected because " +
                                                "it was missing the mandatory 'Content-Type' header.");
            }

            // May have media/type; charset=utf-8, allow partial match.
            if (!Request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                return HandleRequestResult.Fail("The authentication response was rejected because an invalid Content-Type header " +
                                                "was received: make sure to use 'application/x-www-form-urlencoded'.");
            }

            message = new OpenIdAuthenticationMessage(await Request.ReadFormAsync(Context.RequestAborted));
        }

        // Ensure that the current request corresponds to an OpenID 2.0 assertion.
        if (!string.Equals(message.Namespace, OpenIdAuthenticationConstants.Namespaces.OpenId, StringComparison.Ordinal))
        {
            return HandleRequestResult.Fail("The authentication response was rejected because it was missing the mandatory " +
                                            "'openid.ns' parameter or because an unsupported version of OpenID was used.");
        }

        // Stop processing the message if the authentication process was cancelled by the user.
        if (string.Equals(message.Mode, OpenIdAuthenticationConstants.Modes.Cancel, StringComparison.Ordinal))
        {
            return HandleRequestResult.Fail("The authentication response was rejected because " +
                                            "the operation was cancelled by the user.");
        }

        // Stop processing the message if an error was returned by the provider.
        else if (string.Equals(message.Mode, OpenIdAuthenticationConstants.Modes.Error, StringComparison.Ordinal))
        {
            if (string.IsNullOrEmpty(message.Error))
            {
                return HandleRequestResult.Fail("The authentication response was rejected because an " +
                                                "unspecified error was returned by the identity provider.");
            }

            return HandleRequestResult.Fail("The authentication response was rejected because " +
                                           $"an error was returned by the identity provider: {message.Error}.");
        }

        // At this point, stop processing the message if the assertion was not positive.
        else if (!string.Equals(message.Mode, OpenIdAuthenticationConstants.Modes.IdRes, StringComparison.Ordinal))
        {
            return HandleRequestResult.Fail("The authentication response was rejected because " +
                                            "the identity provider declared it as invalid.");
        }

        // Stop processing the message if the assertion
        // was not validated by the identity provider.
        if (!await VerifyAssertionAsync(message))
        {
            return HandleRequestResult.Fail("The authentication response was rejected by the identity provider.");
        }

        var address = QueryHelpers.AddQueryString(uri: properties.Items[OpenIdAuthenticationConstants.Properties.ReturnTo]!,
                                                  name: OpenIdAuthenticationConstants.Parameters.State, value: state!);

        // Validate the return_to parameter by comparing it to the address stored in the properties.
        // See http://openid.net/specs/openid-authentication-2_0.html#verify_return_to for more information.
        if (!string.Equals(message.ReturnTo, address, StringComparison.Ordinal))
        {
            return HandleRequestResult.Fail("The authentication response was rejected because the return_to parameter was invalid.");
        }

        // Make sure the OpenID 2.0 assertion contains an identifier.
        if (string.IsNullOrEmpty(message.ClaimedIdentifier))
        {
            return HandleRequestResult.Fail("The authentication response was rejected because it " +
                                            "was missing the mandatory 'claimed_id' parameter.");
        }

        var identity = new ClaimsIdentity(Scheme.Name);

        // Add the claimed identifier to the identity.
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, message.ClaimedIdentifier, ClaimValueTypes.String, Options.ClaimsIssuer));

        // Add the most common attributes to the identity.
        var attributes = message.GetAttributes();
        foreach (var attribute in attributes)
        {
            // http://axschema.org/contact/email
            if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Email, StringComparison.Ordinal))
            {
                identity.AddClaim(new Claim(ClaimTypes.Email, attribute.Value, ClaimValueTypes.Email, Options.ClaimsIssuer));
            }

            // http://axschema.org/namePerson
            else if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Name, StringComparison.Ordinal))
            {
                identity.AddClaim(new Claim(ClaimTypes.Name, attribute.Value, ClaimValueTypes.String, Options.ClaimsIssuer));
            }

            // http://axschema.org/namePerson/first
            else if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Firstname, StringComparison.Ordinal))
            {
                identity.AddClaim(new Claim(ClaimTypes.GivenName, attribute.Value, ClaimValueTypes.String, Options.ClaimsIssuer));
            }

            // http://axschema.org/namePerson/last
            else if (string.Equals(attribute.Key, OpenIdAuthenticationConstants.Attributes.Lastname, StringComparison.Ordinal))
            {
                identity.AddClaim(new Claim(ClaimTypes.Surname, attribute.Value, ClaimValueTypes.String, Options.ClaimsIssuer));
            }
        }

        // Create a ClaimTypes.Name claim using ClaimTypes.GivenName and ClaimTypes.Surname
        // if the http://axschema.org/namePerson attribute cannot be found in the assertion.
        if (!identity.HasClaim(claim => string.Equals(claim.Type, ClaimTypes.Name, StringComparison.OrdinalIgnoreCase)) &&
             identity.HasClaim(claim => string.Equals(claim.Type, ClaimTypes.GivenName, StringComparison.OrdinalIgnoreCase)) &&
             identity.HasClaim(claim => string.Equals(claim.Type, ClaimTypes.Surname, StringComparison.OrdinalIgnoreCase)))
        {
            identity.AddClaim(new Claim(ClaimTypes.Name, $"{identity.FindFirst(ClaimTypes.GivenName)!.Value} " +
                                                         $"{identity.FindFirst(ClaimTypes.Surname)!.Value}",
                                        ClaimValueTypes.String, Options.ClaimsIssuer));
        }

        var ticket = await CreateTicketAsync(identity, properties, message.ClaimedIdentifier, attributes);
        if (ticket == null)
        {
            Log.SkippedDueToNullTicket(Logger);

            return HandleRequestResult.SkipHandler();
        }

        return HandleRequestResult.Success(ticket);
    }

    protected virtual async Task<AuthenticationTicket> CreateTicketAsync(
        [NotNull] ClaimsIdentity identity, [NotNull] AuthenticationProperties properties,
        [NotNull] string identifier, [NotNull] IReadOnlyDictionary<string, string> attributes)
    {
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);

        var context = new OpenIdAuthenticatedContext(Context, Scheme, Options, ticket);

        // Copy the attributes to the context object.
        foreach (var attribute in attributes)
        {
            context.Attributes.Add(attribute);
        }

        await Events.Authenticated(context);

        // Note: return the authentication ticket associated
        // with the notification to allow replacing the ticket.
        return context.Ticket;
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var configuration = await Options.ConfigurationManager!.GetConfigurationAsync(Context.RequestAborted);
        if (configuration == null)
        {
            throw new AuthenticationFailureException("The OpenID 2.0 authentication middleware was unable to retrieve " +
                                                     "the provider configuration from the OpenID 2.0 authentication server.");
        }

        if (string.IsNullOrEmpty(configuration.AuthenticationEndpoint))
        {
            throw new AuthenticationFailureException("The OpenID 2.0 authentication middleware was unable to retrieve " +
                                                     "the authentication endpoint address from the discovery document.");
        }

        // Determine the realm using the current address
        // if one has not been explicitly provided;
        var realm = Options.Realm;
        if (string.IsNullOrEmpty(realm))
        {
            realm = Request.Scheme + "://" + Request.Host + OriginalPathBase;
        }

        // Use the current address as the final location where the user agent
        // will be redirected to if one has not been explicitly provided.
        if (string.IsNullOrEmpty(properties.RedirectUri))
        {
            properties.RedirectUri = Request.Scheme + "://" + Request.Host +
                                     OriginalPathBase + Request.Path + Request.QueryString;
        }

        // Store the return_to parameter for later comparison.
        properties.Items[OpenIdAuthenticationConstants.Properties.ReturnTo] =
            Request.Scheme + "://" + Request.Host +
            OriginalPathBase + Options.CallbackPath;

        // Generate a new anti-forgery token.
        GenerateCorrelationId(properties);

        // Create a new message containing the OpenID 2.0 request parameters.
        // See http://openid.net/specs/openid-authentication-2_0.html#requesting_authentication
        var message = new OpenIdAuthenticationMessage
        {
            ClaimedIdentifier = "http://specs.openid.net/auth/2.0/identifier_select",
            Identity = "http://specs.openid.net/auth/2.0/identifier_select",
            Mode = OpenIdAuthenticationConstants.Modes.CheckIdSetup,
            Namespace = OpenIdAuthenticationConstants.Namespaces.OpenId,
            Realm = realm,
            ReturnTo = QueryHelpers.AddQueryString(
                uri: properties.Items[OpenIdAuthenticationConstants.Properties.ReturnTo]!,
                name: OpenIdAuthenticationConstants.Parameters.State,
                value: Options.StateDataFormat!.Protect(properties))
        };

        if (Options.Attributes.Count != 0)
        {
            // openid.ns.ax (http://openid.net/srv/ax/1.0)
            message.SetParameter(
                prefix: OpenIdAuthenticationConstants.Prefixes.Namespace,
                name: OpenIdAuthenticationConstants.Aliases.Ax,
                value: OpenIdAuthenticationConstants.Namespaces.Ax);

            // openid.ax.mode (fetch_request)
            message.SetParameter(
                prefix: OpenIdAuthenticationConstants.Prefixes.Ax,
                name: OpenIdAuthenticationConstants.Parameters.Mode,
                value: OpenIdAuthenticationConstants.Modes.FetchRequest);

            foreach (var attribute in Options.Attributes)
            {
                message.SetParameter(
                    prefix: OpenIdAuthenticationConstants.Prefixes.Ax,
                    name: $"{OpenIdAuthenticationConstants.Prefixes.Type}.{attribute.Key}",
                    value: attribute.Value);
            }

            // openid.ax.required
            message.SetParameter(
                prefix: OpenIdAuthenticationConstants.Prefixes.Ax,
                name: OpenIdAuthenticationConstants.Parameters.Required,
                value: string.Join(",", Options.Attributes.Select(attribute => attribute.Key)));
        }

        var context = new OpenIdRedirectContext(Context, Scheme, Options, properties, message);

        await Events.RedirectToIdentityProvider(context);

        var parameters = new Dictionary<string, string?>();
        foreach (var parameter in message.GetParameters())
        {
            parameters[parameter.Key] = parameter.Value;
        }
        var address = QueryHelpers.AddQueryString(configuration.AuthenticationEndpoint, parameters);

        Response.Redirect(address);
    }

    private async Task<bool> VerifyAssertionAsync([NotNull] OpenIdAuthenticationMessage message)
    {
        var configuration = await Options.ConfigurationManager!.GetConfigurationAsync(Context.RequestAborted);
        if (configuration == null)
        {
            throw new AuthenticationFailureException("The OpenID 2.0 authentication middleware was unable to retrieve " +
                                                     "the provider configuration from the OpenID 2.0 authentication server.");
        }

        if (string.IsNullOrEmpty(configuration.AuthenticationEndpoint))
        {
            throw new AuthenticationFailureException("The OpenID 2.0 authentication middleware was unable to retrieve " +
                                                     "the authentication endpoint address from the discovery document.");
        }

        // Create a new message to store the parameters sent to the identity provider.
        // Note: using a dictionary is safe as OpenID 2.0 parameters are supposed to be unique.
        // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
        var payload = new Dictionary<string, string>
        {
            [$"{OpenIdAuthenticationConstants.Prefixes.OpenId}." +
                OpenIdAuthenticationConstants.Parameters.Mode] = OpenIdAuthenticationConstants.Modes.CheckAuthentication
        };

        // Copy the parameters extracted from the assertion.
        foreach (var parameter in message.GetParameters())
        {
            if (string.Equals(parameter.Key, $"{OpenIdAuthenticationConstants.Prefixes.OpenId}." +
                                                OpenIdAuthenticationConstants.Parameters.Mode, StringComparison.Ordinal))
            {
                continue;
            }

            // Note: the "state" parameter is ignored as it is not part of the
            // OpenID message but directly flowed in the return_to parameter.
            if (string.Equals(parameter.Key, OpenIdAuthenticationConstants.Parameters.State, StringComparison.Ordinal))
            {
                continue;
            }

            payload.Add(parameter.Key, parameter.Value);
        }

        // Create a new check_authentication request to verify the assertion.
        using var request = new HttpRequestMessage(HttpMethod.Post, configuration.AuthenticationEndpoint)
        {
            Content = new FormUrlEncodedContent(payload!)
        };

        using var response = await Options.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            Log.InvalidCheckAuthenticationHttpError(
                Logger,
                response.StatusCode,
                response.Headers.ToString(),
                await response.Content.ReadAsStringAsync(Context.RequestAborted));

            return false;
        }

        using var stream = await response.Content.ReadAsStreamAsync(Context.RequestAborted);
        using var reader = new StreamReader(stream);

        // Create a new dictionary containing the parameters extracted from the response body.
        var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

        // Note: the response is encoded using the 'Key-Value Form Encoding'.
        // See http://openid.net/specs/openid-authentication-2_0.html#anchor4
        for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync())
        {
            var parameter = line.Split(':');
            if (parameter.Length != 2)
            {
                continue;
            }

            parameters.Add(parameter[0], parameter[1]);
        }

        // Stop processing the assertion if the mandatory is_valid
        // parameter was missing from the response body.
        if (!parameters.TryGetValue(OpenIdAuthenticationConstants.Parameters.IsValid, out var isValid))
        {
            Log.InvalidCheckAuthenticationResponse(Logger);
            return false;
        }

        // Stop processing the assertion if the authentication server declared it as invalid.
        if (!string.Equals(isValid, "true", StringComparison.Ordinal))
        {
            Log.InvalidSecurityAssertion(Logger);
            return false;
        }

        return true;
    }

    private static partial class Log
    {
        [LoggerMessage(1, LogLevel.Information, "The authentication process was skipped because returned a null ticket was returned.")]
        internal static partial void SkippedDueToNullTicket(ILogger logger);

        [LoggerMessage(2, LogLevel.Warning, "The authentication failed because an invalid check_authentication response was received: " +
                                            "the identity provider returned a {Status} response with the following payload: {Headers} {Body}.")]
        internal static partial void InvalidCheckAuthenticationHttpError(
            ILogger logger,
            HttpStatusCode status,
            string headers,
            string body);

        [LoggerMessage(3, LogLevel.Warning, "The authentication response was rejected because the identity provider " +
                                            "returned an invalid check_authentication response.")]
        internal static partial void InvalidCheckAuthenticationResponse(ILogger logger);

        [LoggerMessage(4, LogLevel.Warning, "The authentication response was rejected because the identity provider " +
                                            "declared the security assertion as invalid.")]
        internal static partial void InvalidSecurityAssertion(ILogger logger);
    }
}
