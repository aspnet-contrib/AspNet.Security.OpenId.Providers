/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Mvc.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseStaticFiles();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                LoginPath = new PathString("/signin"),
                LogoutPath = new PathString("/signout")
            });

            app.UseOpenIdAuthentication(options =>
            {
                options.AuthenticationScheme = "Orange";
                options.DisplayName = "Orange";
                options.Authority = new Uri("https://openid.orange.fr/");
                options.CallbackPath = new PathString("/signin-orange");
            });

            app.UseOpenIdAuthentication(options =>
            {
                options.AuthenticationScheme = "StackExchange";
                options.DisplayName = "StackExchange";
                options.Authority = new Uri("https://openid.stackexchange.com/");
                options.CallbackPath = new PathString("/signin-stackexchange");
            });

            app.UseOpenIdAuthentication(options =>
            {
                options.AuthenticationScheme = "Intuit";
                options.DisplayName = "Intuit";
                options.CallbackPath = new PathString("/signin-intuit");
                options.Configuration = new OpenIdAuthenticationConfiguration
                {
                    AuthenticationEndpoint = "https://openid.intuit.com/OpenId/Provider"
                };
            });

            app.UseSteamAuthentication();

            app.UseMvc();
        }
    }
}