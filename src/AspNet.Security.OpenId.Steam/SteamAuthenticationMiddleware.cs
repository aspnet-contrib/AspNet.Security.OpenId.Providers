/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenId.Steam
{
    public class SteamAuthenticationMiddleware : OpenIdAuthenticationMiddleware<SteamAuthenticationOptions>
    {
        public SteamAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<SteamAuthenticationOptions> options,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IOptions<SharedAuthenticationOptions> externalOptions)
            : base(next, options, dataProtectionProvider, loggerFactory, encoder, externalOptions)
        {
        }

        protected override AuthenticationHandler<SteamAuthenticationOptions> CreateHandler()
        {
            return new SteamAuthenticationHandler();
        }
    }
}
