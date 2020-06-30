/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace AspNet.Security.OpenId.Infrastructure
{
    /// <summary>
    /// A delegating HTTP handler that loops back HTTP requests to external login providers to the local sign-in endpoint.
    /// </summary>
    internal sealed class LoopbackRedirectHandler : DelegatingHandler
    {
        internal string? UserIdentity { get; set; }

        internal IDictionary<string, string>? UserAttributes { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var result = await base.SendAsync(request, cancellationToken);

            // Follow the redirects to external services, assuming they are OpenID Connect-based
            if (result.StatusCode == System.Net.HttpStatusCode.Found &&
                !string.Equals(result.Headers.Location?.Host, "localhost", StringComparison.OrdinalIgnoreCase))
            {
                // Rewrite the URI to loop back to the redirected URL to simulate the user having
                // successfully authenticated with the external login page they were redirected to.
                var queryStringServer = HttpUtility.ParseQueryString(result.Headers.Location!.Query);

                string location = queryStringServer["openid.return_to"]!;

                var locationUri = new Uri(location, UriKind.Absolute);
                var queryStringSelf = HttpUtility.ParseQueryString(locationUri.Query);

                queryStringSelf.Add("code", "a6ed8e7f-471f-44f1-903b-65946475f351");

                foreach (var key in queryStringServer.AllKeys)
                {
                    if (key?.StartsWith("openid.", StringComparison.Ordinal) == true &&
                        !string.Equals(key, "openid.return_to", StringComparison.Ordinal))
                    {
                        queryStringSelf.Add(key, queryStringServer[key]);
                    }
                }

                // Add the appropriate parameters to satisfy the validation when looping back
                queryStringSelf["openid.mode"] = "id_res";
                queryStringSelf["openid.return_to"] = location;

                if (!string.IsNullOrEmpty(UserIdentity))
                {
                    queryStringSelf["openid.claimed_id"] = UserIdentity;
                    queryStringSelf["openid.identity"] = UserIdentity;
                }

                if (UserAttributes != null)
                {
                    foreach (var pair in UserAttributes)
                    {
                        queryStringSelf[$"openid.ax.value.{pair.Key}"] = pair.Value;
                    }
                }

                var builder = new UriBuilder(location)
                {
                    Query = queryStringSelf.ToString(),
                };

                var redirectRequest = new HttpRequestMessage(request.Method, builder.Uri);

                // Forward on the headers and cookies
                foreach (var header in result.Headers)
                {
                    redirectRequest.Headers.Add(header.Key, header.Value);
                }

                redirectRequest.Headers.Add("Cookie", result.Headers.GetValues("Set-Cookie"));

                // Follow the redirect URI
                return await base.SendAsync(redirectRequest, cancellationToken);
            }

            return result;
        }
    }
}
