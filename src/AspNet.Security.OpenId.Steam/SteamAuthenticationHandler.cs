/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenId.Steam
{
    public class SteamAuthenticationHandler : OpenIdAuthenticationHandler<SteamAuthenticationOptions>
    {
        public SteamAuthenticationHandler(
            [NotNull] IOptionsMonitor<SteamAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity, [NotNull] AuthenticationProperties properties,
            [NotNull] string identifier, [NotNull] IReadOnlyDictionary<string, string> attributes)
        {
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, properties, Scheme.Name);

            // Return the authentication ticket as-is if the
            // user information endpoint has not been set.
            if (string.IsNullOrEmpty(Options.UserInformationEndpoint))
            {
                Logger.LogInformation("The userinfo request was skipped because no userinfo endpoint was configured.");

                return ticket;
            }

            // Return the authentication ticket as-is
            // if the application key has not been set.
            if (string.IsNullOrEmpty(Options.ApplicationKey))
            {
                Logger.LogInformation("The userinfo request was skipped because no application key was configured.");

                return ticket;
            }

            // Note: prior to April 2018, the Steam identifier was prefixed with an HTTP base address.
            // Since then, the prefix is now an HTTPS address. The following logic supports both prefixes.
            if (identifier.StartsWith(SteamAuthenticationConstants.Namespaces.Identifier, StringComparison.Ordinal))
            {
                identifier = identifier.Substring(SteamAuthenticationConstants.Namespaces.Identifier.Length);
            }

            else if (identifier.StartsWith(SteamAuthenticationConstants.Namespaces.LegacyIdentifier, StringComparison.Ordinal))
            {
                identifier = identifier.Substring(SteamAuthenticationConstants.Namespaces.LegacyIdentifier.Length);
            }

            // Return the authentication ticket as-is if the claimed identifier is malformed.
            else
            {
                Logger.LogWarning("The userinfo request was skipped because an invalid identifier was received: {Identifier}.", identifier);

                return ticket;
            }

            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                [SteamAuthenticationConstants.Parameters.Key] = Options.ApplicationKey,
                [SteamAuthenticationConstants.Parameters.SteamId] = identifier
            });

            var request = new HttpRequestMessage(HttpMethod.Get, address);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(OpenIdAuthenticationConstants.Media.Json));

            // Return the authentication ticket as-is if the userinfo request failed.
            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogWarning("The userinfo request failed because an invalid response was received: the identity provider " +
                                  "returned returned a {Status} response with the following payload: {Headers} {Body}.",
                                  /* Status: */ response.StatusCode,
                                  /* Headers: */ response.Headers.ToString(),
                                  /* Body: */ await response.Content.ReadAsStringAsync());

                return ticket;
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            // Try to extract the profile name of the authenticated user.
            var profile = payload.Value<JObject>(SteamAuthenticationConstants.Parameters.Response)
                                ?.Value<JArray>(SteamAuthenticationConstants.Parameters.Players)
                            ?[0]?.Value<string>(SteamAuthenticationConstants.Parameters.Name);

            if (!string.IsNullOrEmpty(profile))
            {
                identity.AddClaim(new Claim(ClaimTypes.Name, profile, ClaimValueTypes.String, Options.ClaimsIssuer));
            }

            var context = new OpenIdAuthenticatedContext(Context, Scheme, Options, ticket)
            {
                User = payload
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

        private new OpenIdAuthenticationEvents Events => (OpenIdAuthenticationEvents) base.Events;
    }
}
