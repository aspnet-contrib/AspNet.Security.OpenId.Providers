/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenId.Steam;

public static class SteamAuthenticationConstants
{
    public static class Namespaces
    {
        public const string Identifier = "https://steamcommunity.com/openid/id/";
        public const string LegacyIdentifier = "http://steamcommunity.com/openid/id/";
    }

    public static class Parameters
    {
        public const string Key = "key";
        public const string SteamId = "steamid";
        public const string Response = "response";
        public const string Players = "players";
        public const string Name = "personaname";
    }
}
