/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using Microsoft.Extensions.DependencyInjection;

namespace AspNet.Security.OpenId.Steam
{
    public class SteamTests : OpenIdTests<SteamAuthenticationOptions>
    {
        public SteamTests(ITestOutputHelper outputHelper)
        {
            OutputHelper = outputHelper;
            Interceptor.ThrowOnMissingRegistration = true;

            UserAttributes["email"] = "john@john-smith.local";
            UserAttributes["first"] = "John";
            UserAttributes["namePerson"] = "John Smith";
        }

        public override string DefaultScheme => SteamAuthenticationDefaults.AuthenticationScheme;

        public override string UserIdentity => "https://steamcommunity.com/openid/id/my-id";

        protected internal override void RegisterAuthentication(AuthenticationBuilder builder)
        {
            builder.AddSteam(options =>
            {
                ConfigureDefaults(builder, options);
                options.ApplicationKey = "steam-application-key";
            });
        }

        [Theory]
        [InlineData(ClaimTypes.NameIdentifier, "https://steamcommunity.com/openid/id/my-id")]
        [InlineData(ClaimTypes.Name, "John Smith")]
        [InlineData(ClaimTypes.Email, "john@john-smith.local")]
        [InlineData(ClaimTypes.GivenName, "John")]
        public async Task Can_Sign_In_Using_Steam(string claimType, string claimValue)
        {
            // Arrange
            using var server = CreateTestServer();

            // Act
            var claims = await AuthenticateUserAsync(server);

            // Assert
            AssertClaim(claims, claimType, claimValue);
        }
    }
}
