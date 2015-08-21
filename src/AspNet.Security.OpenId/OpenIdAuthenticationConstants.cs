/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OpenId {
    internal static class OpenIdAuthenticationConstants {
        public static class Aliases {
            public const string Ax = "ax";
        }

        public static class Prefixes {
            public const string OpenId = "openid.";
            public const string Namespace = "ns.";
            public const string Ax = "ax.";
            public const string Type = "type.";
        }

        public static class Suffixes {
            public const string Type = ".type";
        }

        public static class Parameters {
            public const string Namespace = "ns";
            public const string Mode = "mode";
            public const string IsValid = "is_valid";
            public const string ReturnTo = "return_to";
            public const string ClaimedId = "claimed_id";
            public const string Identity = "identity";
            public const string Realm = "realm";
            public const string Required = "required";
            public const string State = "state";
        }

        public static class Namespaces {
            public const string OpenId = "http://specs.openid.net/auth/2.0";
            public const string Ax = "http://openid.net/srv/ax/1.0";
        }

        public static class Modes {
            public const string IdRes = "id_res";
            public const string CheckIdSetup = "checkid_setup";
            public const string CheckAuthentication = "check_authentication";
            public const string FetchRequest = "fetch_request";
        }

        public static class Attributes {
            public const string Email = "http://axschema.org/contact/email";
            public const string Name = "http://axschema.org/namePerson";
            public const string Firstname = "http://axschema.org/namePerson/first";
            public const string Lastname = "http://axschema.org/namePerson/last";
        }
    }
}
