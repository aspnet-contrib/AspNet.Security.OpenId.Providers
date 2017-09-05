﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authentication;

namespace AspNet.Security.OpenId.Steam
{
    /// <summary>
    /// Contains various constants used as default values
    /// for the Steam authentication middleware.
    /// </summary>
    public static class SteamAuthenticationDefaults
    {
        /// <summary>
        /// Gets the default value associated with <see cref="AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = "Steam";

        /// <summary>
        /// Gets the default value associated with <see cref="AuthenticationScheme.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "Steam";

        /// <summary>
        /// Gets the default value associated with <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-steam";

        /// <summary>
        /// Gets the default value associated with <see cref="OpenIdAuthenticationOptions.Authority"/>.
        /// </summary>
        public const string Authority = "https://steamcommunity.com/openid/";

        /// <summary>
        /// Gets the default value associated with <see cref="SteamAuthenticationOptions.UserInformationEndpoint"/>.
        /// </summary>
        public const string UserInformationEndpoint = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/";
    }
}
