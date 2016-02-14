/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using AspNet.Security.OpenId;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Mvc.Client {
    public class Startup {
        public static void Main(string[] args) {
            var application = new WebHostBuilder()
                .UseDefaultConfiguration(args)
                .UseIISPlatformHandlerUrl()
                .UseServer("Microsoft.AspNetCore.Server.Kestrel")
                .UseStartup<Startup>()
                .Build();

            application.Run();
        }

        public void ConfigureServices(IServiceCollection services) {
            services.AddAuthentication(options => {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            });

            services.AddMvc();
        }

        public void Configure(IApplicationBuilder app) {
            var factory = app.ApplicationServices.GetRequiredService<ILoggerFactory>();
            factory.AddConsole();

            app.UseIISPlatformHandler();

            app.UseForwardedHeaders(new ForwardedHeadersOptions {
                ForwardedHeaders = ForwardedHeaders.All
            });

            app.UseStaticFiles();

            app.UseCookieAuthentication(new CookieAuthenticationOptions {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                AuthenticationScheme = CookieAuthenticationDefaults.AuthenticationScheme,
                LoginPath = new PathString("/signin")
            });

            app.UseOpenIdAuthentication(new OpenIdAuthenticationOptions {
                AuthenticationScheme = "Orange",
                DisplayName = "Orange",
                Authority = new Uri("http://orange.fr/"),
                CallbackPath = new PathString("/signin-orange")
            });

            app.UseOpenIdAuthentication(new OpenIdAuthenticationOptions {
                AuthenticationScheme = "StackExchange",
                DisplayName = "StackExchange",
                Authority = new Uri("https://openid.stackexchange.com/"),
                CallbackPath = new PathString("/signin-stackexchange")
            });

            app.UseOpenIdAuthentication(new OpenIdAuthenticationOptions {
                AuthenticationScheme = "Intuit",
                DisplayName = "Intuit",
                CallbackPath = new PathString("/signin-intuit"),
                Endpoint = new Uri("https://openid.intuit.com/OpenId/Provider")
            });

            app.UseSteamAuthentication();

            app.UseMvc();
        }
    }
}