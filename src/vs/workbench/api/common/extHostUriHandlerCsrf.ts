/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type * as vscode from 'vscode';
import { Disposable, IDisposable, toDisposable } from '../../../base/common/lifecycle.js';
import { isString } from '../../../base/common/types.js';
import { URI } from '../../../base/common/uri.js';
import { ExtensionIdentifier, IExtensionDescription } from '../../../platform/extensions/common/extensions.js';
import { createDecorator } from '../../../platform/instantiation/common/instantiation.js';
import { resolveUriHandlerCsrfManifest, stripCsrfToken } from '../../../platform/uriHandler/common/uriHandlerCsrf.js';

export const IExtHostUriHandlerCsrf = createDecorator<IExtHostUriHandlerCsrf>('IExtHostUriHandlerCsrf');

/** How an incoming uri should be dispatched to a registered handler, once CSRF has had its say. */
export type UriHandlerCsrfDecision =
	/** Invoke the handler with this uri (unprotected, exempt, or verified — token stripped). */
	| { readonly kind: 'dispatch'; readonly uri: URI }
	/** Do not invoke the handler; the caller surfaces a rejection notification. */
	| { readonly kind: 'reject' };

/**
 * Owns the CSRF lifecycle for `vscode.UriHandler` registrations: resolving whether a handler is
 * protected, materialising and rotating the signing secret, and deciding how each incoming uri is
 * dispatched. `ExtHostUrls` delegates to this so its own logic stays about routing, not crypto.
 */
export interface IExtHostUriHandlerCsrf {
	readonly _serviceBrand: undefined;

	/**
	 * Wire up CSRF for a handler registration. Resolves the config (manifest is authoritative, the
	 * runtime option is a fallback), materialises the secret so a companion tool can sign the first
	 * link, and starts rotation. Returns a disposable that tears this registration down; a no-op when
	 * the handler is not protected.
	 */
	initialize(extension: IExtensionDescription, options?: vscode.UriHandlerOptions): IDisposable;

	/** Decide how an incoming uri should be dispatched. Reserved parameters are always stripped. */
	handle(extension: IExtensionDescription, uri: URI): Promise<UriHandlerCsrfDecision>;
}

/** Resolved CSRF config for a protected handler (`undefined` means protection is off). */
export interface IResolvedUriHandlerCsrf {
	readonly unprotectedPaths: ReadonlySet<string>;
	/** Explicit secret path from the runtime option (already a resolved uri). */
	readonly secretFile?: URI;
	/** Secret path from the manifest — a raw string spec the store resolves against global storage. */
	readonly secretFileSpec?: string;
	/** What to do where CSRF can't be enforced (a web extension host, or Windows for now). */
	readonly unsupportedPlatforms: 'allow' | 'reject';
}

/**
 * Resolve CSRF config from the manifest (authoritative) or the runtime option (fallback). Pure and
 * platform-independent; the values come from untrusted `package.json`, so malformed security policy
 * fails closed instead of silently weakening protection.
 */
export function resolveUriHandlerCsrf(extension: IExtensionDescription, options?: vscode.UriHandlerOptions): IResolvedUriHandlerCsrf | undefined {
	const manifest = resolveUriHandlerCsrfManifest(extension.contributes?.uriHandler);
	if (manifest) {
		return {
			secretFileSpec: manifest.secretFileSpec,
			unprotectedPaths: manifest.unprotectedPaths,
			unsupportedPlatforms: manifest.unsupportedPlatforms,
		};
	}

	const optionValue: unknown = options?.csrfProtection;
	if (optionValue === undefined) {
		return undefined;
	}
	if (typeof optionValue !== 'object' || optionValue === null || Array.isArray(optionValue)) {
		return { unprotectedPaths: new Set(), unsupportedPlatforms: 'reject' };
	}
	const option = optionValue as Record<string, unknown>;
	const knownProperties = new Set(['secretFile', 'unprotectedPaths', 'unsupportedPlatforms']);
	const malformed = Object.keys(option).some(key => !knownProperties.has(key))
		|| (option.secretFile !== undefined && !URI.isUri(option.secretFile))
		|| (option.unprotectedPaths !== undefined && (!Array.isArray(option.unprotectedPaths) || !option.unprotectedPaths.every(isString)))
		|| (option.unsupportedPlatforms !== 'allow' && option.unsupportedPlatforms !== 'reject');
	return {
		secretFile: URI.isUri(option.secretFile) ? option.secretFile : undefined,
		unprotectedPaths: new Set(!malformed && Array.isArray(option.unprotectedPaths) && option.unprotectedPaths.every(isString) ? option.unprotectedPaths : []),
		unsupportedPlatforms: option.unsupportedPlatforms === 'allow' && !malformed ? 'allow' : 'reject',
	};
}

/**
 * Implementation for environments with no trustworthy local filesystem (web worker extension host).
 * CSRF can't be enforced — there is no local secret a remote page cannot also reach — so a protected
 * handler either fails closed (every non-exempt link rejected) or, if it opted out, dispatches
 * unprotected. Protected handlers are tracked in either case so reserved parameters are stripped.
 */
export class NullExtHostUriHandlerCsrf implements IExtHostUriHandlerCsrf {
	declare readonly _serviceBrand: undefined;

	private readonly configs = new Map<string, { readonly unprotectedPaths: ReadonlySet<string>; readonly unsupportedPlatforms: 'allow' | 'reject' }>();

	initialize(extension: IExtensionDescription, options?: vscode.UriHandlerOptions): IDisposable {
		const resolved = resolveUriHandlerCsrf(extension, options);
		if (!resolved) {
			return Disposable.None;
		}
		const key = ExtensionIdentifier.toKey(extension.identifier);
		this.configs.set(key, { unprotectedPaths: resolved.unprotectedPaths, unsupportedPlatforms: resolved.unsupportedPlatforms });
		return toDisposable(() => this.configs.delete(key));
	}

	async handle(extension: IExtensionDescription, uri: URI): Promise<UriHandlerCsrfDecision> {
		const config = this.configs.get(ExtensionIdentifier.toKey(extension.identifier));
		if (!config) {
			return { kind: 'dispatch', uri: stripCsrfToken(uri) };
		}
		if (config.unprotectedPaths.has(uri.path) || config.unsupportedPlatforms === 'allow') {
			return { kind: 'dispatch', uri: stripCsrfToken(uri) };
		}
		return { kind: 'reject' };
	}
}
