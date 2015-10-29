/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using Microsoft.AspNet.Authentication;

namespace AspNet.Security.OpenId {
    public interface IOpenIdAuthenticationEvents : IRemoteAuthenticationEvents {
        Task Authenticated(OpenIdAuthenticatedContext context);
    }
}
