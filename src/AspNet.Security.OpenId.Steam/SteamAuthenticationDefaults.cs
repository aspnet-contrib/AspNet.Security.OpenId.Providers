/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenId.Steam {
    public static class SteamAuthenticationDefaults {
        public const string AuthenticationScheme = "Steam";

        public const string DisplayName = "Steam";

        public const string Authority = "http://steamcommunity.com/openid/";

        public const string CallbackPath = "/signin-steam";
    }
}
