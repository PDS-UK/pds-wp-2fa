# Composer packaging and runtime baseline for PDS WP 2FA

**Context pointer:** [Wayfinder ticket: Choose Composer packaging and support baseline for PDS WP 2FA](https://github.com/PDS-UK/pds-wp-2fa/issues/4)

**Research date:** 2026-08-24

## Decision summary

PDS WP 2FA should be published as a Composer package named `pds/wp-2fa` with
`type: wordpress-plugin`. It should require `composer/installers` as an
install-time dependency, use `PDS\\WP2FA\\` → `src/` PSR-4 autoloading, and
resolve its PHP dependencies in the consuming site's Composer project.

The supported deployment contract should be:

| Concern | Recommendation |
| --- | --- |
| Composer package | `pds/wp-2fa`, `type: wordpress-plugin` |
| Install-time installer | `composer/installers:^2.3`; package `extra.installer-name: pds-wp-2fa` |
| Runtime loading | The site's generated `vendor/autoload.php`; no Composer CLI on the web server |
| PHP | `>=8.3` |
| WordPress | `>=6.8`, with the latest stable major as the primary supported/tested version |
| Composer CLI | Composer 2.x; Composer 2.2+ is the practical minimum because of `allow-plugins` |
| WebAuthn browser baseline | HTTPS secure context, JavaScript enabled, top-level same-origin page, and feature detection for `PublicKeyCredential` plus `navigator.credentials.create/get` |
| WebAuthn server extensions | `ext-json` and `ext-openssl` |
| Locking | The consuming site's `composer.lock` is authoritative; do not require consumers to use a lock file shipped by the plugin package |

The WordPress floor and browser policy are product recommendations rather than
claims that older WordPress versions or browsers cannot run the code. The
implementation should raise or revisit the WordPress floor if it adopts APIs
newer than 6.8.

## Evidence and implications

### Package type, metadata, and autoloading

Composer's schema says that `type` defaults to `library`, and that custom types
such as `wordpress-plugin` only affect installation when a suitable installer
is available. Composer also recommends PSR-4 and requires namespace prefixes to
end in a trailing backslash. See the [Composer package schema](https://getcomposer.org/doc/04-schema.md#type)
and [Composer PSR-4 schema guidance](https://getcomposer.org/doc/04-schema.md#psr-4).

The package should therefore contain metadata equivalent to:

```json
{
  "name": "pds/wp-2fa",
  "type": "wordpress-plugin",
  "license": "GPL-2.0-or-later",
  "autoload": {
    "psr-4": {
      "PDS\\WP2FA\\": "src/"
    }
  },
  "autoload-dev": {
    "psr-4": {
      "PDS\\WP2FA\\Tests\\": "tests/"
    }
  },
  "extra": {
    "installer-name": "pds-wp-2fa"
  }
}
```

The `installer-name` is deliberate: the official `composer/installers`
documentation supports package authors setting the final installation name,
independent of the Composer package name. Keep the package's installation path
configurable by the consuming project rather than embedding a `wp-content`
path in the plugin. See [composer/installers custom install names](https://github.com/composer/installers#custom-install-names).

The plugin's main PHP file should remain at the root of the installed plugin
directory, for example `pds-wp-2fa.php`. WordPress scans the plugins directory
for PHP files with plugin headers, and the file containing the plugin metadata is
the file WordPress includes as the plugin's main execution file. See the
[WordPress plugin basics](https://developer.wordpress.org/plugins/plugin-basics/)
and [`get_plugins()` reference](https://developer.wordpress.org/reference/functions/get_plugins/).

### Installer arrangement

`composer/installers` officially supports the `wordpress-plugin` package type.
Its WordPress installer maps plugins to `wp-content/plugins/{$name}/` by
default, and its supported source maps the `wordpress-plugin` type to that
installer. See the [supported package types](https://github.com/composer/installers#supported-frameworks)
and [WordPress installer source](https://raw.githubusercontent.com/composer/installers/main/src/Composer/Installers/WordPressInstaller.php).

The package should require `composer/installers:^2.3` so a consumer does not
silently install the plugin as an ordinary `vendor/pds/wp-2fa` library. The
consumer's Composer configuration must explicitly allow the Composer plugin:

```json
{
  "config": {
    "allow-plugins": {
      "composer/installers": true
    }
  }
}
```

Composer documents `allow-plugins` as a security control and defaults it to no
plugins allowed. See [Composer plugin configuration](https://getcomposer.org/doc/06-config.md#allow-plugins).

#### Bedrock

Bedrock should keep its project-specific installer paths, typically:

```json
{
  "extra": {
    "installer-paths": {
      "web/app/plugins/{$name}/": ["type:wordpress-plugin"]
    }
  }
}
```

This follows Bedrock's published `composer.json` convention, which also puts
Composer dependencies in the project-level `vendor/` directory and keeps the
public document root under `web/`. See the [Bedrock Composer configuration](https://roots.io/bedrock/#dependencies-in-composer-json)
and [Bedrock directory structure](https://roots.io/bedrock/#bedrock-structure).

#### Standard single-site WordPress

A standard installation can use a project-level `composer.json` beside the
WordPress installation and the default installer path, or make it explicit:

```json
{
  "extra": {
    "installer-paths": {
      "wp-content/plugins/{$name}/": ["type:wordpress-plugin"]
    }
  }
}
```

The path belongs in the consuming project because WordPress permits custom
content directories; plugin code must not assume that the directory is named
`wp-content`. See [WordPress directory guidance](https://developer.wordpress.org/plugins/plugin-basics/determining-plugin-and-content-directories/)
and [composer/installers custom install paths](https://github.com/composer/installers#custom-install-paths).

### Runtime dependency loading and deployment

Composer generates `vendor/autoload.php` for packages with autoload metadata.
The consuming project should run Composer in CI or a build environment, then
deploy the generated `vendor/` tree and installed plugin files. Composer's
documentation recommends committing the lock file for projects and using
`composer install` from that lock file for reproducible deployments. It also
states that committing a lock file is not necessary for libraries; PDS WP 2FA
is consumed as a package, so the application's lock file—not a plugin-local
lock file—is the dependency contract. See [Composer autoloading and lock files](https://getcomposer.org/doc/01-basic-usage.md#autoloading)
and [Composer dependency installation](https://getcomposer.org/doc/01-basic-usage.md#installing-dependencies).

The release/deployment rule should be:

```text
build:   composer install --no-dev --prefer-dist --optimize-autoloader
deploy:  plugin files + vendor/ + the consuming project's composer.lock
runtime: PHP loads vendor/autoload.php; Composer CLI is not required
```

`--optimize-autoloader` is recommended for production by Composer. Do not use
`--classmap-authoritative` by default until the plugin and all dependencies have
been verified not to generate classes dynamically; Composer documents that this
option can cause class-not-found failures for generated classes. See [Composer autoloader optimization](https://getcomposer.org/doc/articles/autoloader-optimization.md)
and the [`install` options](https://getcomposer.org/doc/03-cli.md#install-i).

The plugin bootstrap should use this loading order:

1. If the required classes are already available, use the site's existing
   Composer autoloader.
2. Otherwise, load an explicitly documented project autoloader path, then the
   conventional project-level `vendor/autoload.php` location for a standard
   WordPress layout.
3. If no dependency autoloader is available, fail with a clear setup error and
   do not start a partially initialized authentication system.

Bedrock already loads the project Composer autoloader early in `wp-config.php`,
so the plugin must not install or load a second copy of its dependencies. Roots'
autoloading guidance explicitly describes Bedrock's site dependencies as being
loaded early in `wp-config.php`. See [Roots namespacing and autoloading](https://roots.io/namespacing-and-autoloading/#composer-and-namespacing).

For standard WordPress, document that Composer must be run from the project
root and that the resulting `vendor/` directory must be deployed with the site.
The plugin should support a project-level autoloader without requiring a
plugin-local `vendor/` directory. A separate, PDS-built bundled ZIP could be
offered later for sites that cannot maintain a project-level Composer build, but
that would be a different distribution artifact and is not part of the
Composer package contract.

### Runtime dependencies

The first implementation should use maintained packages rather than custom
cryptography:

```json
{
  "require": {
    "php": ">=8.3",
    "composer/installers": "^2.3",
    "spomky-labs/otphp": "^11.6",
    "web-auth/webauthn-lib": "^5.3"
  }
}
```

The exact constraints should be revalidated when implementation begins. The
current `web-auth/webauthn-lib` package metadata requires PHP 8.2 or newer,
`ext-json`, and `ext-openssl`, and exposes its `Webauthn\\` namespace through
PSR-4. See the [WebAuthn library package metadata](https://raw.githubusercontent.com/web-auth/webauthn-lib/5.3.x/composer.json).
The current OTPHP metadata requires PHP 8.1 or newer and provides RFC 4226/RFC
6238 TOTP support. See [OTPHP package metadata](https://raw.githubusercontent.com/Spomky-Labs/otphp/11.6.x/composer.json).

The PHP 8.3 project floor is intentionally higher than either library's floor:
it matches WordPress's current recommended PHP baseline and the current Bedrock
project baseline, while leaving room for the modern language and security
features expected by this plugin. See [WordPress requirements](https://wordpress.org/about/requirements/)
and [Bedrock's current Composer requirements](https://roots.io/bedrock/#dependencies-in-composer-json).

The local QR-code renderer should remain a normal PHP dependency selected during
the TOTP implementation. If `bacon/bacon-qr-code` is used, its package metadata
requires `ext-iconv` and only suggests `ext-imagick`; this should be reflected in
the final package metadata and README. See [BaconQrCode package metadata](https://raw.githubusercontent.com/Bacon/BaconQrCode/main/composer.json).

## Minimum platform contract

### PHP and WordPress

- **PHP:** `>=8.3`. The plugin header should use `Requires PHP: 8.3`, and the
  package should declare the same Composer platform requirement.
- **WordPress:** `>=6.8` for the first release. Test the lowest supported
  version and the latest stable major. WordPress's current release archive says
  that only the most recent major series is actively maintained, so deployment
  documentation should strongly recommend the latest stable WordPress rather
  than presenting 6.8 as an indefinitely supported LTS. See the [WordPress
  release archive](https://wordpress.org/download/releases/) and [supported
  versions policy](https://wordpress.org/documentation/article/supported-versions/).
- **HTTPS:** required in production. WordPress lists HTTPS as required, and
  the WebAuthn specification exposes the API only to secure contexts. See
  [WordPress requirements](https://wordpress.org/about/requirements/) and the
  [Web Authentication API security model](https://www.w3.org/TR/webauthn-3/#sctn-api-security).
- **Multisite:** not supported in phase one. Do not add a network-level
  Composer or activation contract.

### Browser/WebAuthn

Do not encode a brittle browser-version allowlist in the plugin. The minimum
functional WebAuthn contract is:

- JavaScript enabled;
- a secure HTTPS context in production;
- a top-level page in the plugin's expected origin;
- `PublicKeyCredential` available; and
- `navigator.credentials.create({publicKey: ...})` and
  `navigator.credentials.get({publicKey: ...})` available and usable.

The implementation must feature-detect these capabilities and hide or disable
WebAuthn when they are unavailable. The supported QA matrix should cover the
current stable Chrome, Edge, Firefox, and Safari families plus the platform
authenticators that the project claims to support. TOTP and recovery codes must
remain usable in browsers without WebAuthn support.

This capability-based policy follows the WebAuthn specification: the API is
secure-context-only, credentials are scoped to an origin/RP ID, and the browser
mediates `navigator.credentials.create()` and `get()`. See the [WebAuthn API specification](https://www.w3.org/TR/webauthn-3/) for the API, secure-context, RP ID, and origin-validation requirements.

Per the existing project decision, production is the only environment in which
WebAuthn enrollment/authentication is offered. Local, development, and staging
may disable WebAuthn and may use an explicit enforcement bypass, but a missing
or unknown environment value must not silently weaken production.

## Release metadata and source layout

Every release should include:

1. `composer.json` with the package name/type, PHP and runtime requirements,
   PSR-4/autoload-dev mappings, installer name, license, keywords, homepage,
   authors, and Composer `support` links for issues, source, documentation, and
   security reporting. Composer defines these metadata fields in its [package
   schema](https://getcomposer.org/doc/04-schema.md).
2. A root plugin file containing WordPress headers including `Plugin Name`,
   `Version`, `Requires at least`, `Requires PHP`, `Update URI`, `License`, and
   `Text Domain`. WordPress documents these fields in [Header Requirements](https://developer.wordpress.org/plugins/plugin-basics/header-requirements/).
3. SemVer Git tags such as `v1.0.0`. Do not hard-code a `version` field in
   `composer.json`; Composer recommends allowing VCS/Packagist to infer package
   versions from tags. The plugin header remains the WordPress runtime metadata
   source.
4. `README.md` covering both Bedrock and standard WordPress installation,
   build/deploy expectations, PHP/WordPress/browser requirements, Composer
   plugin approval, environment policy, and the fact that Composer CLI is not a
   production runtime requirement.
5. A changelog and security reporting policy linked from the Composer `support`
   metadata and release notes.

The repository may keep a lock file for its own development/CI fixture if that
helps reproducibility, but consumers should resolve the plugin and its
dependencies through their own root `composer.lock`. CI should validate the
package, install with `--no-dev`, run `composer audit`, and run
`composer check-platform-reqs` against the production artifact. Composer
documents `check-platform-reqs` as checking the real production platform rather
than only the configured platform override; see [Composer CLI reference](https://getcomposer.org/doc/03-cli.md#check-platform-reqs).

## Handoff consequences

This decision leaves the implementation tickets with a stable deployment
contract:

- The plugin bootstrap must be independent of the physical `wp-content` path.
- The plugin must use the consuming site's Composer autoloader and must not
  assume dependencies are installed inside the plugin directory.
- Bedrock configuration is project-owned; the plugin only declares its package
  type and installer name.
- Standard WordPress users need a project-level Composer build and must deploy
  `vendor/`; installing only the plugin directory is insufficient for its PHP
  dependencies.
- Composer installer approval, package security auditing, and lock-file
  management belong in deployment documentation and CI.
- WebAuthn UI and server code must be capability-detected and must retain TOTP
  as the non-WebAuthn path.
