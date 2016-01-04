/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Internal;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenId {
    /// <summary>
    /// Exposes various information about the current OpenID authentication flow.
    /// </summary>
    public class OpenIdAuthenticatedContext : BaseControlContext {
        public OpenIdAuthenticatedContext(
            [NotNull] HttpContext context,
            [NotNull] OpenIdAuthenticationOptions options,
            [NotNull] AuthenticationTicket ticket)
            : base(context) {
            Options = options;
            AuthenticationTicket = ticket;
        }

        /// <summary>
        /// Gets the options used by the OpenID authentication middleware.
        /// </summary>
        public OpenIdAuthenticationOptions Options { get; }

        /// <summary>
        /// Gets the identifier returned by the identity provider.
        /// </summary>
        public string Identifier => AuthenticationTicket?.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        /// <summary>
        /// Gets or sets the attributes associated with the current user.
        /// </summary>
        public IDictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

        /// <summary>
        /// Gets or sets the optional JSON payload extracted from the current request.
        /// This property is not set by the generic middleware but can be used by specialized middleware.
        /// </summary>
        public JObject User { get; set; } = new JObject();
    }
}
