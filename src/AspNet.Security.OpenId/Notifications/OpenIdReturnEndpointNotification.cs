/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Http;
using Microsoft.Framework.Internal;

namespace AspNet.Security.OpenId.Notifications {
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class OpenIdReturnEndpointNotification : ReturnEndpointContext {
        /// <summary>
        /// Initializes a <see cref="OpenIdReturnEndpointNotification"/>
        /// </summary>
        /// <param name="context">The <see cref="HttpContext"/> corresponding to the current request.</param>
        /// <param name="ticket">The authentication ticket.</param>
        public OpenIdReturnEndpointNotification(
            [NotNull] HttpContext context,
            [NotNull] AuthenticationTicket ticket)
            : base(context, ticket) {
        }
    }
}
