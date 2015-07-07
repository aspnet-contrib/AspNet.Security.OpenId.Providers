using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNet.Authentication.Notifications;
using Microsoft.AspNet.Http;
using Microsoft.AspNet.Http.Authentication;
using Microsoft.Framework.Internal;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OpenId.Notifications {
    public class OpenIdAuthenticatedNotification : BaseNotification<OpenIdAuthenticationOptions> {
        public OpenIdAuthenticatedNotification(
            [NotNull] HttpContext context,
            [NotNull] OpenIdAuthenticationOptions options)
            : base(context, options) {
        }

        public ClaimsPrincipal Principal { get; set; }

        public AuthenticationProperties Properties { get; set; }

        public string Identifier { get; [param: NotNull] set; }

        public IReadOnlyDictionary<string, string> Attributes { get; [param: NotNull] set; } = ImmutableDictionary.Create<string, string>();

        public JObject User { get; [param: NotNull] set; } = new JObject();
    }
}
