/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.AspNet.Authentication;
using Microsoft.AspNet.Builder;
using Microsoft.AspNet.DataProtection;
using Microsoft.Framework.Internal;
using Microsoft.Framework.Logging;
using Microsoft.Framework.OptionsModel;
using Microsoft.Framework.WebEncoders;

namespace AspNet.Security.OpenId.Steam {
    public class SteamAuthenticationMiddleware : OpenIdAuthenticationMiddleware<SteamAuthenticationOptions> {
        public SteamAuthenticationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] SteamAuthenticationOptions options,
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] IUrlEncoder encoder,
            [NotNull] IOptions<SharedAuthenticationOptions> externalOptions)
            : base(next, options, dataProtectionProvider, loggerFactory, encoder, externalOptions) {
        }

        protected override AuthenticationHandler<SteamAuthenticationOptions> CreateHandler() {
            return new SteamAuthenticationHandler();
        }
    }
}
