/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using AspNet.Security.OpenId;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class OpenIdAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OpenId authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOpenId([NotNull] this AuthenticationBuilder builder)
            => builder.AddOpenId(OpenIdAuthenticationDefaults.AuthenticationScheme, _ => { });

        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OpenId authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="configuration">The delegate used to configure the OpenId options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOpenId([NotNull] this AuthenticationBuilder builder, [NotNull] Action<OpenIdAuthenticationOptions> configuration)
            => builder.AddOpenId(OpenIdAuthenticationDefaults.AuthenticationScheme, configuration);

        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OpenId authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The AuthenticationScheme name for the scheme.</param>
        /// <param name="configuration">The delegate used to configure the OpenId options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOpenId([NotNull] this AuthenticationBuilder builder, [NotNull] string authenticationScheme, [NotNull] Action<OpenIdAuthenticationOptions> configuration)
            => builder.AddOpenId(authenticationScheme, OpenIdAuthenticationDefaults.DisplayName, configuration);

        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OpenId authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The AuthenticationScheme name for the scheme.</param>
        /// <param name="displayName">The DisplayName for the scheme.</param>
        /// <param name="configuration">The delegate used to configure the OpenId options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOpenId([NotNull] this AuthenticationBuilder builder, [NotNull] string authenticationScheme, [NotNull] string displayName, [NotNull] Action<OpenIdAuthenticationOptions> configuration)
        {
            return builder.AddOpenId<OpenIdAuthenticationOptions, OpenIdAuthenticationHandler<OpenIdAuthenticationOptions>>(authenticationScheme, displayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables OpenId authentication capabilities.
        /// </summary>
        /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
        /// <param name="authenticationScheme">The AuthenticationScheme name for the scheme.</param>
        /// <param name="displayName">The DisplayName for the scheme.</param>
        /// <param name="configuration">The delegate used to configure the OpenId options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddOpenId<TOptions, THandler>([NotNull] this AuthenticationBuilder builder, [NotNull] string authenticationScheme, [NotNull] string displayName, [NotNull] Action<TOptions> configuration)
            where TOptions : OpenIdAuthenticationOptions, new()
            where THandler : OpenIdAuthenticationHandler<TOptions>
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>, OpenIdAuthenticationInitializer<TOptions, THandler>>());
            return builder.AddRemoteScheme<TOptions, THandler>(authenticationScheme, displayName, configuration);
        }
    }
}
