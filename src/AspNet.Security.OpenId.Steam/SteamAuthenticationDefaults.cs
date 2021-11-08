/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenId.Steam;

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
    public static readonly string DisplayName = "Steam";

    /// <summary>
    /// Gets the default value associated with <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
    /// </summary>
    public static readonly string CallbackPath = "/signin-steam";

    /// <summary>
    /// Gets the default value associated with <see cref="OpenIdAuthenticationOptions.Authority"/>.
    /// </summary>
    public static readonly string Authority = "https://steamcommunity.com/openid/";

    /// <summary>
    /// Gets the default value associated with <see cref="SteamAuthenticationOptions.UserInformationEndpoint"/>.
    /// </summary>
    public static readonly string UserInformationEndpoint = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/";
}
