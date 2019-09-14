/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace Mvc.Client
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })

            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.LogoutPath = "/signout";
            })

            .AddOpenId("Orange", "Orange", options =>
            {
                options.Authority = new Uri("https://openid.orange.fr/");
                options.CallbackPath = "/signin-orange";
            })

            .AddOpenId("StackExchange", "StackExchange", options =>
            {
                options.Authority = new Uri("https://openid.stackexchange.com/");
                options.CallbackPath = "/signin-stackexchange";
            })

            .AddOpenId("Intuit", "Intuit", options =>
            {
                options.CallbackPath = "/signin-intuit";
                options.Configuration = new OpenIdAuthenticationConfiguration
                {
                    AuthenticationEndpoint = "https://openid.intuit.com/OpenId/Provider"
                };
            })

            .AddSteam();

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
        }

        public void Configure(IApplicationBuilder app)
        {
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
