/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

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
