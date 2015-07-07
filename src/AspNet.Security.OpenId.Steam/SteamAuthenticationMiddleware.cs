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
            [NotNull] IDataProtectionProvider dataProtectionProvider,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] IUrlEncoder encoder,
            [NotNull] IOptions<ExternalAuthenticationOptions> externalOptions,
            [NotNull] IOptions<SteamAuthenticationOptions> options,
            ConfigureOptions<SteamAuthenticationOptions> configureOptions = null)
            : base(next, dataProtectionProvider, loggerFactory,
                   encoder, externalOptions, options, configureOptions) {
        }

        protected override AuthenticationHandler<SteamAuthenticationOptions> CreateHandler() {
            return new SteamAuthenticationHandler();
        }
    }
}
