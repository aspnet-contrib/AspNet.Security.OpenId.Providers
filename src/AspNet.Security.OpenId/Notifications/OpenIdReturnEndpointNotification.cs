using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Authentication.Notifications;
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
