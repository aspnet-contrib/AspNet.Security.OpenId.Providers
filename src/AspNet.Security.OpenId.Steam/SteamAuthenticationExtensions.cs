/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using AspNet.Security.OpenId.Steam;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Exposes convenient extensions that can be used to add an instance
    /// of the Steam authentication middleware in an ASP.NET 5 pipeline.
    /// </summary>
    public static class SteamAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddSteam([NotNull] this AuthenticationBuilder builder)
        => builder.AddSteam(SteamAuthenticationDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="configuration">The delegate used to configure the Steam options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddSteam([NotNull] this AuthenticationBuilder builder, [NotNull] Action<SteamAuthenticationOptions> configuration)
        => builder.AddSteam(SteamAuthenticationDefaults.AuthenticationScheme, configuration);

        /// <summary>
        /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The AuthenticationScheme name for the scheme.</param>
        /// <param name="configuration">The delegate used to configure the Steam options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddSteam([NotNull] this AuthenticationBuilder builder, [NotNull] string authenticationScheme, [NotNull] Action<SteamAuthenticationOptions> configuration)
        => builder.AddSteam(authenticationScheme, SteamAuthenticationDefaults.DisplayName, configuration);

        /// <summary>
        /// Adds <see cref="SteamAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Steam authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The AuthenticationScheme name for the scheme.</param>
        /// <param name="displayName">The DisplayName for the scheme.</param>
        /// <param name="configuration">The delegate used to configure the Steam options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddSteam([NotNull] this AuthenticationBuilder builder, [NotNull] string authenticationScheme, [NotNull] string displayName, [NotNull] Action<SteamAuthenticationOptions> configuration)
        => builder.AddOpenId<SteamAuthenticationOptions, SteamAuthenticationHandler>(authenticationScheme, displayName, configuration);
    }
}
