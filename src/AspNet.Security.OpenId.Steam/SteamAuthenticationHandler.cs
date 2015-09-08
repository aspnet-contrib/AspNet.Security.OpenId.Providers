/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.AspNet.WebUtilities;
using Microsoft.Framework.Internal;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenId.Steam {
    public class SteamAuthenticationHandler : OpenIdAuthenticationHandler<SteamAuthenticationOptions> {
        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity, [NotNull] AuthenticationProperties properties,
            [NotNull] string identifier, [NotNull] IDictionary<string, string> attributes) {
            var principal = new ClaimsPrincipal(identity);

            // Return the authentication ticket as-is
            // if the application key cannot be found.
            if (string.IsNullOrEmpty(Options.AppKey)) {
                return new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            }

            // Return the authentication ticket as-is if the claimed identifier is malformed.
            if (!identifier.StartsWith(SteamAuthenticationConstants.Namespaces.Identifier, StringComparison.Ordinal)) {
                return new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            }

            var address = QueryHelpers.AddQueryString("http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/", new Dictionary<string, string> {
                [SteamAuthenticationConstants.Parameters.Key] = Options.AppKey,
                [SteamAuthenticationConstants.Parameters.SteamId] = identifier.Substring(SteamAuthenticationConstants.Namespaces.Identifier.Length)
            });

            var request = new HttpRequestMessage(HttpMethod.Get, address);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await Options.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);

            // Return the authentication ticket as-is
            // if the GetPlayerSummaries request failed.
            if (!response.IsSuccessStatusCode) {
                return new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            // Try to extract the profile name of the authenticated user.
            var profile = payload.Value<JObject>(SteamAuthenticationConstants.Parameters.Response)
                                ?.Value<JArray>(SteamAuthenticationConstants.Parameters.Players)
                            ?[0]?.Value<string>(SteamAuthenticationConstants.Parameters.Name);

            if (!string.IsNullOrEmpty(profile)) {
                identity.AddClaim(new Claim(ClaimTypes.Name, profile, ClaimValueTypes.String, Options.ClaimsIssuer));
            }
            
            var context = new OpenIdAuthenticatedContext(Context, Options) {
                Attributes = attributes.ToImmutableDictionary(),
                Principal = principal, Properties = properties,
                Identifier = identifier, User = payload
            };

            await Options.Events.Authenticated(context);

            if (context.Principal?.Identity == null) {
                return new AuthenticationTicket(properties, Options.AuthenticationScheme);
            }

            return new AuthenticationTicket(principal, properties, Options.AuthenticationScheme);
        }
    }
}
