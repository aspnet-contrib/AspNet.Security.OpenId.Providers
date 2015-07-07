using System;
using System.Threading.Tasks;
using AspNet.Security.OpenId.Notifications;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationProvider : IOpenIdAuthenticationProvider {
        public Func<OpenIdAuthenticatedNotification, Task> OnAuthenticated { get; set; } = notification => Task.FromResult<object>(null);
        public Func<OpenIdReturnEndpointNotification, Task> OnReturnEndpoint { get; set; } = notification => Task.FromResult<object>(null);

        public virtual Task Authenticated(OpenIdAuthenticatedNotification notification) => OnAuthenticated(notification);
        public virtual Task ReturnEndpoint(OpenIdReturnEndpointNotification notification) => OnReturnEndpoint(notification);
    }
}
