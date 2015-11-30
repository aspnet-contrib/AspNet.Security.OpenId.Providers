AspNet.Security.OpenId.Providers
==================================

**AspNet.Security.OpenId.Providers** is a **collection of security middleware** that you can use in your **ASP.NET 5** application to support OpenID 2.0 authentication providers like **[Steam](http://steampowered.com/)**, **[Wargaming](http://wargaming.net/)** or **[Orange](http://www.orange.fr/)**. It is directly inspired by **[Jerrie Pelser](https://github.com/jerriep)**'s initiative, **[Owin.Security.Providers](https://github.com/RockstarLabs/OwinOAuthProviders)**.

**The latest official release can be found on [NuGet](https://www.nuget.org/profiles/aspnet-contrib) and the nightly builds on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

[![Build status](https://ci.appveyor.com/api/projects/status/tc9n807mwi4sr5jd/branch/dev?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-openid-providers/branch/dev)
[![Build status](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenId.Providers.svg?branch=dev)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OpenId.Providers)

## Getting started

**Adding external authentication to your application is a breeze** and just requires a few lines in your `Startup` class:

    app.UseSteamAuthentication();

See [https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/tree/dev/samples/Mvc.Client](https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers/tree/dev/samples/Mvc.Client) for a complete sample **using MVC 6 and supporting multiple external providers**.

## Support

**Need help or wanna share your thoughts? Don't hesitate to join our dedicated chat rooms:**

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OpenId.Providers](https://gitter.im/aspnet-contrib/AspNet.Security.OpenId.Providers)**

## Contributors

**AspNet.Security.OpenId.Providers** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)** ([@PinpointTownes](https://twitter.com/PinpointTownes)) and **[Jerrie Pelser](https://github.com/jerriep)** ([@jerriepelser](https://twitter.com/jerriepelser)). Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.