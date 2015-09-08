/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;

namespace AspNet.Security.OpenId {
    public class OpenIdAuthenticationEvents : IOpenIdAuthenticationEvents {
        public Func<OpenIdAuthenticatedContext, Task> OnAuthenticated { get; set; } = context => Task.FromResult<object>(null);
        public Func<OpenIdReturnEndpointContext, Task> OnReturnEndpoint { get; set; } = context => Task.FromResult<object>(null);

        public virtual Task Authenticated(OpenIdAuthenticatedContext context) => OnAuthenticated(context);
        public virtual Task ReturnEndpoint(OpenIdReturnEndpointContext context) => OnReturnEndpoint(context);
    }
}
