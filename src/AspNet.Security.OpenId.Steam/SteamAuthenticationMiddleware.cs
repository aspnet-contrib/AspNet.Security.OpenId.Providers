/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.DataProtection;
using Microsoft.AspNet.Http;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OpenId.Steam {
    public class SteamAuthenticationMiddleware : OpenIdAuthenticationMiddleware<SteamAuthenticationOptions> {
        public SteamAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] SteamAuthenticationOptions options,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IOptions<SharedAuthenticationOptions> externalOptions)
            : base(next, options, dataProtectionProvider, loggerFactory, encoder, externalOptions) {
        }

        protected override AuthenticationHandler<SteamAuthenticationOptions> CreateHandler() {
            return new SteamAuthenticationHandler();
        }
    }
}
