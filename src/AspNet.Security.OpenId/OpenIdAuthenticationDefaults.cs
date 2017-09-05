/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.OpenId
{
    /// <summary>
    /// Contains various constants used as default values
    /// for the OpenID authentication middleware.
    /// </summary>
    public static class OpenIdAuthenticationDefaults
    {
        /// <summary>
        /// Gets the default value associated with <see cref="AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = "OpenId";

        /// <summary>
        /// Gets the default value associated with <see cref="AuthenticationScheme.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "OpenId";

        /// <summary>
        /// Gets the default value associated with <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-openid";
    }
}
