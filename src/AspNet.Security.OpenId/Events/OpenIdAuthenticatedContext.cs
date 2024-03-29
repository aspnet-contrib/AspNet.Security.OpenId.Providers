﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OpenId;

/// <summary>
/// Exposes various information about the current OpenID authentication flow.
/// </summary>
public class OpenIdAuthenticatedContext(
    [NotNull] HttpContext context,
    [NotNull] AuthenticationScheme scheme,
    [NotNull] OpenIdAuthenticationOptions options,
    [NotNull] AuthenticationTicket ticket) : BaseContext<OpenIdAuthenticationOptions>(context, scheme, options)
{
    /// <summary>
    /// Gets or sets the authentication ticket.
    /// </summary>
    public AuthenticationTicket Ticket { get; set; } = ticket;

    /// <summary>
    /// Gets the identity containing the claims associated with the current user.
    /// </summary>
    public ClaimsIdentity? Identity => Ticket?.Principal?.Identity as ClaimsIdentity;

    /// <summary>
    /// Gets the identifier returned by the identity provider.
    /// </summary>
    public string? Identifier => Ticket?.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    /// <summary>
    /// Gets the authentication properties associated with the ticket.
    /// </summary>
    public AuthenticationProperties? Properties => Ticket?.Properties;

    /// <summary>
    /// Gets or sets the attributes associated with the current user.
    /// </summary>
    public IDictionary<string, string> Attributes { get; } = new Dictionary<string, string>();

    /// <summary>
    /// Gets or sets the optional JSON payload extracted from the current request.
    /// This property is not set by the generic middleware but can be used by specialized middleware.
    /// </summary>
    public JsonDocument? UserPayload { get; set; }
}
