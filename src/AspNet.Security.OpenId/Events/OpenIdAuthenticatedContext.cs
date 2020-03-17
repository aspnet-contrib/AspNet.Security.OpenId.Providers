/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenId
{
    /// <summary>
    /// Exposes various information about the current OpenID authentication flow.
    /// </summary>
    public class OpenIdAuthenticatedContext : BaseContext<OpenIdAuthenticationOptions>
    {
        public OpenIdAuthenticatedContext(
            [NotNull] HttpContext context,
            [NotNull] AuthenticationScheme scheme,
            [NotNull] OpenIdAuthenticationOptions options,
            [NotNull] AuthenticationTicket ticket)
            : base(context, scheme, options)
        {
            Ticket = ticket;
        }

        /// <summary>
        /// Gets or sets the authentication ticket.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }

        /// <summary>
        /// Gets the identity containing the claims associated with the current user.
        /// </summary>
        public ClaimsIdentity Identity => Ticket?.Principal?.Identity as ClaimsIdentity;

        /// <summary>
        /// Gets the identifier returned by the identity provider.
        /// </summary>
        public string Identifier => Ticket?.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        /// <summary>
        /// Gets the authentication properties associated with the ticket.
        /// </summary>
        public AuthenticationProperties Properties => Ticket?.Properties;

        /// <summary>
        /// Gets or sets the attributes associated with the current user.
        /// </summary>
        public IDictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

        /// <summary>
        /// Gets or sets the optional JSON payload extracted from the current request.
        /// This property is not set by the generic middleware but can be used by specialized middleware.
        /// </summary>
        [Obsolete("Use the UserPayload property instead. This property's type will change from JObject to JsonDocument in a future release.")]
        public JObject User { get; set; } = new JObject();

        /// <summary>
        /// Gets or sets the optional JSON payload extracted from the current request.
        /// This property is not set by the generic middleware but can be used by specialized middleware.
        /// </summary>
        public JsonDocument UserPayload { get; set; }
    }
}
