﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenId;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection;

public static class OpenIdAuthenticationExtensions
{
    /// <summary>
    /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables OpenID 2.0 authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddOpenId([NotNull] this AuthenticationBuilder builder)
    {
        return builder.AddOpenId(OpenIdAuthenticationDefaults.AuthenticationScheme, options => { });
    }

    /// <summary>
    /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables OpenID 2.0 authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddOpenId(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] Action<OpenIdAuthenticationOptions> configuration)
    {
        return builder.AddOpenId(OpenIdAuthenticationDefaults.AuthenticationScheme, configuration);
    }

    /// <summary>
    /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables OpenID 2.0 authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddOpenId(
        [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
        [NotNull] Action<OpenIdAuthenticationOptions> configuration)
    {
        return builder.AddOpenId(scheme, OpenIdAuthenticationDefaults.DisplayName, configuration);
    }

    /// <summary>
    /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables OpenID 2.0 authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="caption">The optional display name associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddOpenId(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme, [CanBeNull] string caption,
        [NotNull] Action<OpenIdAuthenticationOptions> configuration)
    {
        return builder.AddOpenId<OpenIdAuthenticationOptions, OpenIdAuthenticationHandler<OpenIdAuthenticationOptions>>(scheme, caption, configuration);
    }

    /// <summary>
    /// Adds <see cref="OpenIdAuthenticationHandler{TOptions}"/> to the specified
    /// <see cref="AuthenticationBuilder"/>, which enables OpenID 2.0 authentication capabilities.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme associated with this instance.</param>
    /// <param name="caption">The optional display name associated with this instance.</param>
    /// <param name="configuration">The delegate used to configure the OpenID 2.0 options.</param>
    /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
    public static AuthenticationBuilder AddOpenId<TOptions, THandler>(
        [NotNull] this AuthenticationBuilder builder,
        [NotNull] string scheme, [CanBeNull] string caption,
        [NotNull] Action<TOptions> configuration)
        where TOptions : OpenIdAuthenticationOptions, new()
        where THandler : OpenIdAuthenticationHandler<TOptions>
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentNullException.ThrowIfNullOrEmpty(scheme);

        // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
        builder.Services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IPostConfigureOptions<TOptions>,
                                        OpenIdAuthenticationInitializer<TOptions, THandler>>());

        return builder.AddRemoteScheme<TOptions, THandler>(scheme, caption, configuration);
    }
}
