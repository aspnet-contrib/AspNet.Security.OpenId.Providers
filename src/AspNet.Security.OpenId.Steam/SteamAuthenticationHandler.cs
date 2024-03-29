﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenId.Steam;

public partial class SteamAuthenticationHandler : OpenIdAuthenticationHandler<SteamAuthenticationOptions>
{
    public SteamAuthenticationHandler(
        [NotNull] IOptionsMonitor<SteamAuthenticationOptions> options,
        [NotNull] ILoggerFactory logger,
        [NotNull] UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override async Task<AuthenticationTicket> CreateTicketAsync(
        [NotNull] ClaimsIdentity identity, [NotNull] AuthenticationProperties properties,
        [NotNull] string identifier, [NotNull] IReadOnlyDictionary<string, string> attributes)
    {
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);

        // Return the authentication ticket as-is if the user information endpoint has not been set.
        if (string.IsNullOrEmpty(Options.UserInformationEndpoint))
        {
            Log.NoUserInformationEndpoint(Logger);

            return await RunAuthenticatedEventAsync();
        }

        // Return the authentication ticket as-is if the application key has not been set.
        if (string.IsNullOrEmpty(Options.ApplicationKey))
        {
            Log.NoApplicationKey(Logger);

            return await RunAuthenticatedEventAsync();
        }

        // Note: prior to April 2018, the Steam identifier was prefixed with an HTTP base address.
        // Since then, the prefix is now an HTTPS address. The following logic supports both prefixes.
        if (identifier.StartsWith(SteamAuthenticationConstants.Namespaces.Identifier, StringComparison.Ordinal))
        {
            identifier = identifier[SteamAuthenticationConstants.Namespaces.Identifier.Length..];
        }

        else if (identifier.StartsWith(SteamAuthenticationConstants.Namespaces.LegacyIdentifier, StringComparison.Ordinal))
        {
            identifier = identifier[SteamAuthenticationConstants.Namespaces.LegacyIdentifier.Length..];
        }

        // Prevent the sign-in operation from completing if the claimed identifier is malformed.
        else
        {
            Log.InvalidIdentifier(Logger, identifier);

            throw new AuthenticationFailureException($"The OpenID claimed identifier '{identifier}' is not valid.");
        }

        var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string?>
        {
            [SteamAuthenticationConstants.Parameters.Key] = Options.ApplicationKey,
            [SteamAuthenticationConstants.Parameters.SteamId] = identifier
        });

        using var request = new HttpRequestMessage(HttpMethod.Get, address);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Json));

        // Return the authentication ticket as-is if the userinfo request failed.
        using var response = await Options.Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
        if (!response.IsSuccessStatusCode)
        {
            Log.UserInformationEndpointHttpError(
                Logger,
                response.StatusCode,
                response.Headers.ToString(),
                await response.Content.ReadAsStringAsync(Context.RequestAborted));

            throw new HttpRequestException("An error occurred while retrieving the user profile from Steam.");
        }

        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Context.RequestAborted));

        // Try to extract the profile name of the authenticated user.
        var profile = payload.RootElement
            .GetProperty(SteamAuthenticationConstants.Parameters.Response)
            .GetProperty(SteamAuthenticationConstants.Parameters.Players)
            .EnumerateArray()
            .FirstOrDefault();

        if (profile.ValueKind == JsonValueKind.Object && profile.TryGetProperty(SteamAuthenticationConstants.Parameters.Name, out var name))
        {
            identity.AddClaim(new Claim(ClaimTypes.Name, name.GetString()!, ClaimValueTypes.String, Options.ClaimsIssuer));
        }

        return await RunAuthenticatedEventAsync(payload);

        async Task<AuthenticationTicket> RunAuthenticatedEventAsync(JsonDocument? user = null)
        {
            var context = new OpenIdAuthenticatedContext(Context, Scheme, Options, ticket)
            {
                UserPayload = user
            };

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
    }

    private static partial class Log
    {
        [LoggerMessage(1, LogLevel.Information, "The userinfo request was skipped because no userinfo endpoint was configured.")]
        internal static partial void NoUserInformationEndpoint(ILogger logger);

        [LoggerMessage(2, LogLevel.Information, "The userinfo request was skipped because no application key was configured.")]
        internal static partial void NoApplicationKey(ILogger logger);

        [LoggerMessage(3, LogLevel.Warning, "The userinfo request was skipped because an invalid identifier was received: {Identifier}.")]
        internal static partial void InvalidIdentifier(ILogger logger, string identifier);

        [LoggerMessage(4, LogLevel.Warning, "The userinfo request failed because an invalid response was received: the identity provider " +
                                            "returned returned a {Status} response with the following payload: {Headers} {Body}.")]
        internal static partial void UserInformationEndpointHttpError(
            ILogger logger,
            HttpStatusCode status,
            string headers,
            string body);
    }
}
