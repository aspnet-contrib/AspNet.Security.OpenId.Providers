# AspNet.Security.OpenId.Providers

**AspNet.Security.OpenId.Providers** is a **collection of security middleware** that you can use in your **ASP.NET Core** application to support OpenID 2.0 authentication providers like **[Steam](https://steampowered.com/)**, **[Wargaming](https://wargaming.net/)** or **[Orange](https://www.orange.fr/)**. It is directly inspired by **[Jerrie Pelser](https://github.com/jerriep)**'s initiative, **[Owin.Security.Providers](https://github.com/RockstarLabs/OwinOAuthProviders)**.

**The latest official release can be found on [NuGet](https://www.nuget.org/profiles/aspnet-contrib) and the nightly builds on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

| | Linux/macOS | Windows |
|:-:|:-:|:-:|
| **Build Status** | [![Build status](https://img.shields.io/travis/aspnet-contrib/AspNet.Security.OpenId.Providers/dev.svg)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenId.Providers) | [![Build status](https://img.shields.io/appveyor/ci/aspnet-contrib/aspnet-security-openid-providers/dev.svg)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-openid-providers) |
| **Build History** | [![Build history](https://buildstats.info/travisci/chart/aspnet-contrib/AspNet.Security.OpenId.Providers?branch=dev&includeBuildsFromPullRequest=false)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenId.Providers) |  [![Build history](https://buildstats.info/appveyor/chart/aspnet-contrib/aspnet-security-openid-providers?branch=dev&includeBuildsFromPullRequest=false)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-openid-providers) |

## Getting started

**Adding external authentication to your application is a breeze** and just requires a few lines in your `Startup` class:

```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddAuthentication(options => { /* Authentication options */ })
            .AddSteam()
            .AddOpenId("StackExchange", "StackExchange", options =>
            {
                options.Authority = new Uri("https://openid.stackexchange.com/");
                options.CallbackPath = "/signin-stackexchange";
            });
}

public void Configure(IApplicationBuilder app)
{
    app.UseAuthentication();
}
```

See the [/samples](https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/tree/dev/samples) directory for a complete sample **using ASP.NET Core MVC and supporting multiple external providers**.

## Contributing

**AspNet.Security.OpenId.Providers** is actively maintained by:

  * **[Kévin Chalet](https://github.com/kevinchalet)** ([@PinpointTownes](https://twitter.com/PinpointTownes)).
  * **[Martin Costello](https://github.com/martincostello)** ([@martin_costello](https://twitter.com/martin_costello)).
  * **[Patrick Westerhoff](https://github.com/poke)** ([@poke](https://twitter.com/poke)).

We would love it if you could help contributing to this repository.

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join us on Gitter or ask your question on StackOverflow:

- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OpenId.Providers](https://gitter.im/aspnet-contrib/AspNet.Security.OpenId.Providers)**
- **StackOverflow: [https://stackoverflow.com/questions/tagged/aspnet-contrib](https://stackoverflow.com/questions/tagged/aspnet-contrib)**

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [https://www.apache.org/licenses/LICENSE-2.0.html](https://www.apache.org/licenses/LICENSE-2.0.html) for more details.

## Providers

Links to the latest stable and nightly NuGet packages for each provider, as well as a link to their integration documentation are listed in the table below.

If a provider you're looking for does not exist, consider making a PR to add one.

| Provider | Stable | Nightly | Documentation |
|:-:|:-:|:-:|:-:|
| OpenId | [![NuGet](https://buildstats.info/nuget/AspNet.Security.OpenId?includePreReleases=false)](https://www.nuget.org/packages/AspNet.Security.OpenId/ "Download AspNet.Security.OpenId from NuGet.org") | [![MyGet](https://buildstats.info/myget/aspnet-contrib/AspNet.Security.OpenId?includePreReleases=false)](https://www.myget.org/feed/aspnet-contrib/package/nuget/AspNet.Security.OpenId "Download AspNet.Security.OpenId from MyGet.org") | N/A |
| Steam | [![NuGet](https://buildstats.info/nuget/AspNet.Security.OpenId.Steam?includePreReleases=false)](https://www.nuget.org/packages/AspNet.Security.OpenId.Steam/ "Download AspNet.Security.OpenId.Steam from NuGet.org") | [![MyGet](https://buildstats.info/myget/aspnet-contrib/AspNet.Security.OpenId.Steam?includePreReleases=false)](https://www.myget.org/feed/aspnet-contrib/package/nuget/AspNet.Security.OpenId.Steam "Download AspNet.Security.OpenId.Steam from MyGet.org") | [Documentation](https://steamcommunity.com/dev "Steam developer documentation") |

<!--
| CHANGEME | [![NuGet](https://buildstats.info/nuget/AspNet.Security.OpenId.CHANGEME?includePreReleases=false)](https://www.nuget.org/packages/AspNet.Security.OpenId.CHANGEME/ "Download AspNet.Security.OpenId.CHANGEME from NuGet.org") | [![MyGet](https://buildstats.info/myget/aspnet-contrib/AspNet.Security.OpenId.CHANGEME?includePreReleases=false)](https://www.myget.org/feed/aspnet-contrib/package/nuget/AspNet.Security.OpenId.CHANGEME "Download AspNet.Security.OpenId.CHANGEME from MyGet.org") | [Documentation](CHANGEME "CHANGEME developer documentation") |
-->
