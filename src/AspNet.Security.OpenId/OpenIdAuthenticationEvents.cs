/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using AspNet.Security.OpenId.Events;

namespace AspNet.Security.OpenId;

/// <summary>
/// Specifies callback methods that the <see cref="OpenIdAuthenticationHandler{TOptions}"/>
/// invokes to enable developer control over the OpenID2 authentication process.
/// </summary>
public class OpenIdAuthenticationEvents : RemoteAuthenticationEvents
{
    /// <summary>
    /// Defines a notification invoked when the user is authenticated by the identity provider.
    /// </summary>
    public Func<OpenIdAuthenticatedContext, Task> OnAuthenticated { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Defines a notification invoked prior to redirecting to the identity provider.
    /// </summary>
    public Func<OpenIdRedirectContext, Task> OnRedirectToIdentityProvider { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Defines a notification invoked when the user is authenticated by the identity provider.
    /// </summary>
    /// <param name="context">The context of the event carries information in and results out.</param>
    /// <returns>Task to enable asynchronous execution</returns>
    public virtual Task Authenticated(OpenIdAuthenticatedContext context) => OnAuthenticated(context);

    /// <summary>
    /// Defines a notification invoked prior to redirecting to the identity provider.
    /// </summary>
    /// <param name="context">The context of the event carries information in and results out.</param>
    /// <returns>Task to enable asynchronous execution</returns>
    public virtual Task RedirectToIdentityProvider(OpenIdRedirectContext context) => OnRedirectToIdentityProvider(context);
}
