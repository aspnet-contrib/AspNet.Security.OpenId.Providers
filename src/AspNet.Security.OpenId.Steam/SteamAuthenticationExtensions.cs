﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenId.Steam;

namespace Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Exposes convenient extensions that can be used to add an instance
/// of the Steam authentication middleware in an ASP.NET Core pipeline.
/// </summary>
public static class SteamAuthenticationExtensions
{
    /// <summary>
    /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddSteam([NotNull] this AuthenticationBuilder builder)
    {
        return builder.AddSteam(SteamAuthenticationDefaults.AuthenticationScheme, options => { });
    }

    /// <summary>
    /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddSteam(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] Action<SteamAuthenticationOptions> configuration)
    {
        return builder.AddSteam(SteamAuthenticationDefaults.AuthenticationScheme, configuration);
    }

    /// <summary>
    /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Steam options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddSteam(
        [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
        [NotNull] Action<SteamAuthenticationOptions> configuration)
    {
        return builder.AddSteam(scheme, SteamAuthenticationDefaults.DisplayName, configuration);
    }

    /// <summary>
    /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="caption">The optional display name associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the Steam options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddSteam(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme, [CanBeNull] string caption,
        [NotNull] Action<SteamAuthenticationOptions> configuration)
    {
        return builder.AddOpenId<SteamAuthenticationOptions, SteamAuthenticationHandler>(scheme, caption, configuration);
    }
}
