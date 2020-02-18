/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OpenId.Providers
 * for more information concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using JetBrains.Annotations;
using Microsoft.Extensions.Primitives;

namespace AspNet.Security.OpenId
{
    /// <summary>
    /// Represents an OpenID message.
    /// </summary>
    public class OpenIdAuthenticationMessage
    {
        /// <summary>
        /// Initializes a new OpenID message.
        /// </summary>
        public OpenIdAuthenticationMessage() { }

        /// <summary>
        /// Initializes a new OpenID message.
        /// </summary>
        /// <param name="parameters">The parameters associated with the message.</param>
        public OpenIdAuthenticationMessage([NotNull] IDictionary<string, string> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                Parameters.Add(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Initializes a new OpenID message.
        /// </summary>
        /// <param name="parameters">The parameters associated with the message.</param>
        public OpenIdAuthenticationMessage([NotNull] IEnumerable<KeyValuePair<string, StringValues>> parameters)
        {
            if (parameters == null)
            {
                throw new ArgumentNullException(nameof(parameters));
            }

            foreach (var parameter in parameters)
            {
                if (string.IsNullOrEmpty(parameter.Key))
                {
                    continue;
                }

                Parameters.Add(parameter.Key, parameter.Value);
            }
        }

        /// <summary>
        /// Gets or sets the openid.claimed_id property.
        /// </summary>
        public string ClaimedIdentifier
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.ClaimedId);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.ClaimedId, value);
        }

        /// <summary>
        /// Gets or sets the openid.identity property.
        /// </summary>
        public string Identity
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.Identity);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.Identity, value);
        }

        /// <summary>
        /// Gets or sets the openid.error property.
        /// </summary>
        public string Error
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.Error);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.Error, value);
        }

        /// <summary>
        /// Gets or sets the openid.mode property.
        /// </summary>
        public string Mode
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.Mode);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.Mode, value);
        }

        /// <summary>
        /// Gets or sets the openid.ns property.
        /// </summary>
        public string Namespace
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.Namespace);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.Namespace, value);
        }

        /// <summary>
        /// Gets or sets the openid.realm property.
        /// </summary>
        public string Realm
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.Realm);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.Realm, value);
        }

        /// <summary>
        /// Gets or sets the openid.return_to property.
        /// </summary>
        public string ReturnTo
        {
            get => GetParameter(OpenIdAuthenticationConstants.Parameters.ReturnTo);
            set => SetParameter(OpenIdAuthenticationConstants.Parameters.ReturnTo, value);
        }

        /// <summary>
        /// Gets the parameters associated with this OpenID message.
        /// </summary>
        public IDictionary<string, string> Parameters { get; } =
            new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>
        /// Adds a parameter using the default prefix.
        /// </summary>
        /// <param name="name">The parameter name.</param>
        /// <param name="value">The parameter value.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdAuthenticationMessage AddParameter([NotNull] string name, [CanBeNull] string value)
            => AddParameter(OpenIdAuthenticationConstants.Prefixes.OpenId, name, value);

        /// <summary>
        /// Adds a parameter using the specified prefix.
        /// </summary>
        /// <param name="prefix">The prefix used to discriminate the parameter.</param>
        /// <param name="name">The parameter to store.</param>
        /// <param name="value">The value associated with the parameter.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdAuthenticationMessage AddParameter([NotNull] string prefix, [NotNull] string name, [CanBeNull] string value)
        {
            if (string.IsNullOrEmpty(prefix))
            {
                throw new ArgumentException("The prefix cannot be null or empty.", nameof(prefix));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            if (!Parameters.ContainsKey($"{prefix}.{name}"))
            {
                Parameters.Add($"{prefix}.{name}", value);
            }

            return this;
        }

        /// <summary>
        /// Gets the attributes returned by the identity provider, or an empty
        /// dictionary if the message doesn't expose an attribute exchange alias.
        /// </summary>
        /// <returns>The attributes contained in this message.</returns>
        public IReadOnlyDictionary<string, string> GetAttributes()
        {
            var attributes = new Dictionary<string, string>(StringComparer.Ordinal);

            // If the ax alias cannot be found, return an empty dictionary.
            var extensions = GetExtensions();
            if (!extensions.TryGetValue(OpenIdAuthenticationConstants.Namespaces.Ax, out string alias))
            {
                return attributes;
            }

            foreach (var parameter in Parameters)
            {
                var prefix = $"{OpenIdAuthenticationConstants.Prefixes.OpenId}.{alias}.{OpenIdAuthenticationConstants.Suffixes.Type}.";

                // Exclude parameters that don't correspond to the attribute exchange alias.
                if (!parameter.Key.StartsWith(prefix, StringComparison.Ordinal))
                {
                    continue;
                }

                // Exclude attributes whose alias is malformed.
                var name = parameter.Key.Substring(prefix.Length);
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                // Exclude attributes whose type is missing.
                var type = parameter.Value;
                if (string.IsNullOrEmpty(type))
                {
                    continue;
                }

                // Exclude attributes whose value is missing.
                if (!Parameters.TryGetValue($"{OpenIdAuthenticationConstants.Prefixes.OpenId}.{alias}." +
                                            $"{OpenIdAuthenticationConstants.Suffixes.Value}.{name}", out string value))
                {
                    continue;
                }

                // Exclude attributes whose value is null or empty.
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                attributes.Add(type, value);
            }

            return attributes;
        }

        /// <summary>
        /// Gets the extensions and their corresponding alias.
        /// </summary>
        /// <returns>The extensions contained in this message.</returns>
        public IReadOnlyDictionary<string, string> GetExtensions()
        {
            var extensions = new Dictionary<string, string>(StringComparer.Ordinal);

            foreach (var parameter in Parameters)
            {
                var prefix = $"{OpenIdAuthenticationConstants.Prefixes.Namespace}.";

                if (parameter.Key.StartsWith(prefix, StringComparison.Ordinal))
                {
                    extensions.Add(parameter.Value, parameter.Key.Substring(prefix.Length));
                }
            }

            return extensions;
        }

        /// <summary>
        /// Gets the parameter corresponding to the requested name and the default
        /// prefix or <c>null</c> if no appropriate parameter can be found.
        /// </summary>
        /// <param name="name">The parameter to retrieve.</param>
        /// <returns>The value extracted from the parameter.</returns>
        public string GetParameter([NotNull] string name)
            => GetParameter(OpenIdAuthenticationConstants.Prefixes.OpenId, name);

        /// <summary>
        /// Gets the parameter corresponding to the requested name and the given
        /// prefix or <c>null</c> if no appropriate parameter can be found.
        /// </summary>
        /// <param name="prefix">The prefix used to discriminate the parameter.</param>
        /// <param name="name">The parameter to retrieve.</param>
        /// <returns>The value extracted from the parameter.</returns>
        public string GetParameter([NotNull] string prefix, [NotNull] string name)
        {
            if (string.IsNullOrEmpty(prefix))
            {
                throw new ArgumentNullException(nameof(prefix));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (Parameters.TryGetValue($"{prefix}.{name}", out string value))
            {
                return value;
            }

            return null;
        }

        /// <summary>
        /// Gets all the parameters associated with this instance.
        /// </summary>
        /// <returns>The parameters associated with this instance.</returns>
        public IReadOnlyDictionary<string, string> GetParameters()
            => new ReadOnlyDictionary<string, string>(Parameters);

        /// <summary>
        /// Adds, replaces or removes the parameter corresponding
        /// to the requested name and the default prefix.
        /// </summary>
        /// <param name="name">The parameter to store.</param>
        /// <param name="value">The value associated with the parameter.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdAuthenticationMessage SetParameter([NotNull] string name, [CanBeNull] string value)
            => SetParameter(OpenIdAuthenticationConstants.Prefixes.OpenId, name, value);

        /// <summary>
        /// Adds, replaces or removes the parameter corresponding
        /// to the requested name and the given prefix.
        /// </summary>
        /// <param name="prefix">The prefix used to discriminate the parameter.</param>
        /// <param name="name">The parameter to store.</param>
        /// <param name="value">The value associated with the parameter.</param>
        /// <returns>The current instance, which allows chaining calls.</returns>
        public OpenIdAuthenticationMessage SetParameter([NotNull] string prefix, [NotNull] string name, [CanBeNull] string value)
        {
            if (string.IsNullOrEmpty(prefix))
            {
                throw new ArgumentException("The prefix cannot be null or empty.", nameof(prefix));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The parameter name cannot be null or empty.", nameof(name));
            }

            // If the parameter value is null, remove
            // it from the parameters dictionary.
            if (string.IsNullOrEmpty(value))
            {
                Parameters.Remove($"{prefix}.{name}");
            }

            else
            {
                Parameters[$"{prefix}.{name}"] = value;
            }

            return this;
        }
    }
}
