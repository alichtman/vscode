# CSRF protection for extension URI handlers

If your extension registers a `vscode.UriHandler`, any website can trigger it via a
`vscode://your.extension/...` deeplink. CSRF protection lets you require that a deeplink was created
by a **local process on the same machine** (e.g. your companion CLI), rejecting links a web page
tries to forge.

It works by HMAC-signing the link with a secret that only local processes can read. The browser
can't read the secret, so it can't forge a valid link.

> Use this for routes that do anything sensitive (run code, change state). Leave it off for routes
> that are *meant* to be web-initiated (see [Exempt routes](#exempt-routes)).

---

## 1. Turn it on

Declare it in `package.json` (recommended because it is statically auditable and lets the `code` CLI
locate the signing secret):

```jsonc
"contributes": {
  "uriHandler": {
    "csrfProtection": {
      "unsupportedPlatforms": "reject"
    }
  }
}
```

Or at runtime:

```ts
vscode.window.registerUriHandler(handler, {
  csrfProtection: { unsupportedPlatforms: vscode.UriHandlerUnsupportedPlatformPolicy.Reject }
});
```

The manifest declaration wins if both are present.

URI-triggered activation can occur before verification; the guarantee applies when VS Code dispatches
to `handleUri`, not to extension activation itself. Every protected link that is dispatched reaches
it with the CSRF parameters already stripped, including exempt links and links on platforms
configured with `"allow"`. A forged, expired, or unsigned link never reaches an enforced route (the
user sees a "blocked an unauthenticated link" notification).

---

## 2. Sign links with the `code` CLI

Use `code --sign-extension-uri` on the machine where the extension host runs. It finds the installed
extension's manifest, resolves and provisions its configured secret, and prints a signed URI:

```sh
signed_uri="$(code --sign-extension-uri 'vscode://my.ext/run?task=build')"
code --open-url "$signed_uri"
```

The command uses the selected profile (`--profile` when provided) and refuses extensions without a
valid manifest declaration. This command is the supported signing protocol; companion tools do not
need to parse the secret file or reproduce canonicalization and rotation.

### Remote extension hosts

Sign on the machine where the URI handler's extension host runs. A remote window alone is not enough:
a workspace extension running over SSH or in a dev container signs remotely, while a UI extension
running on the desktop signs locally.

For a remotely running handler:

1. Install the extension on the remote host and declare `csrfProtection` in its manifest. The CLI
   reads the installed manifest without activating the extension, so a runtime-only declaration
   cannot be used for CLI signing.
2. Start the companion tool from an integrated terminal attached to that remote window, or as a
   descendant of that terminal. VS Code gives the terminal a per-terminal CLI pipe through
   `VSCODE_IPC_HOOK_CLI`; an unrelated SSH session does not inherit that pipe address.
3. Ask the remote `code` CLI to sign the URI. It returns the signed URI on standard output:

   ```sh
   signed_uri="$(code --sign-extension-uri 'vscode://my.ext/run?task=build')"
   ```

4. Return the URI to the desktop for opening. From the same integrated terminal, the remote CLI
   bridge can do that directly:

   ```sh
   code --openExternal "$signed_uri"
   ```

   `--openExternal` is specific to the remote integrated-terminal bridge. The desktop
   `code --open-url` form does not traverse that remote pipe.

Internally, the signing request stays on the remote host. The terminal's `code` wrapper sends a
`signExtensionUri` request over its private pipe. The remote server finds the remotely installed
extension, validates the URI authority and manifest policy, resolves the extension's remote global
storage, and provisions or reads the secret there. It signs the path, fragment, timestamp, and all
non-reserved query parameters, then returns only the signed URI. The secret never crosses to the
desktop client.

Opening the result may show the normal extension URI trust prompt and may activate the extension.
The trust dialog hides the globally reserved CSRF parameters, but retains them on the URI sent for
verification. The URI is then dispatched to the remote extension host, which verifies it against the
same remote secret. For an enforced, non-exempt route, only after successful verification are the
reserved parameters stripped and `handleUri` called. Trust, activation, and CSRF verification are
separate steps; a valid signature does not skip the trust prompt, and verification does not prevent
activation side effects.

---

## 3. Exempt routes

Some routes are legitimately opened by a browser and *cannot* be signed — most importantly OAuth
callbacks (`asExternalUri` → `openExternal` → the browser redirects back). Exempt those paths so they
keep working:

```jsonc
"contributes": {
  "uriHandler": {
    "csrfProtection": {
      "unprotectedPaths": ["/did-authenticate"],
      "unsupportedPlatforms": "reject"
    }
  }
}
```

Everything else still requires a valid token. Exempt paths are matched **exactly** and
case-sensitively, and are dispatched without a token.

---

## 4. Unsupported platforms

CSRF enforcement needs a trustworthy local secret, which isn't available everywhere:

- **Web extension hosts** (e.g. `vscode.dev`) have no local filesystem a companion tool could share
  a secret through.
- **Windows** is not enforced yet (it needs per-file ACL checks that aren't implemented).

Every protected handler must choose its behavior explicitly:

- `"reject"` blocks every non-exempt deeplink.
- `"allow"` dispatches non-exempt deeplinks without verification.

```jsonc
"contributes": {
  "uriHandler": {
    "csrfProtection": { "unsupportedPlatforms": "reject" }
  }
}
```

`unsupportedPlatforms` only affects unenforceable platforms. On macOS and Linux every non-exempt
route is verified; exempt [`unprotectedPaths`](#3-exempt-routes) are dispatched without a token
everywhere.

---

## Secret location

The `code` CLI and VS Code share a secret created with owner-only permissions (`0600`) that rotates
automatically. Its file format and rotation protocol are internal; companion tools should invoke
`--sign-extension-uri` rather than reading or creating the file.

- **Default location:** under your extension's global storage,
  `…/User/globalStorage/<your.extension>/uri-csrf.secret`.
- **Override** (for deployments that require a fixed shared location):

  ```jsonc
  "csrfProtection": {
    "secretFile": "${globalStorage}/uri-csrf.secret",
    "unsupportedPlatforms": "reject"
  }
  ```

  `${globalStorage}` resolves to your extension's global storage directory; an absolute path also
  works. Invalid, relative, non-file, or escaping paths are ignored and the default location is used.

The CLI must run as the same user as VS Code, or as a user in the file's group. VS Code rejects a
world-readable or world-writable secret file.

---

## Behavior & limits

- **Links expire after ~4 hours** (via the signed `vscode-csrf-ts`). Timestamps more than five minutes
  in the future are also rejected. Generate links right before opening them; don't persist them.
- **Tamper-evident:** the signature covers the path, fragment, and every parameter, so a captured link
  can't be reused with different arguments — only replayed verbatim within the expiry window.
- **Unsupported platforms (web, Windows):** protected routes follow the required
  [`unsupportedPlatforms`](#4-unsupported-platforms) policy. Exempt routes always work.
- **Reserved parameters:** `vscode-csrf-token` and `vscode-csrf-ts` are stripped before every extension
  URI handler, including handlers that do not enable CSRF protection.
- **Rejections** show the user a notification and are logged (redacted) to the extension-host output.
