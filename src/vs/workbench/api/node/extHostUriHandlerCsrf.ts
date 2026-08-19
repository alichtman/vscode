/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { onUnexpectedError } from '../../../base/common/errors.js';
import { Disposable, IDisposable, toDisposable } from '../../../base/common/lifecycle.js';
import { URI } from '../../../base/common/uri.js';
import { ExtensionIdentifier, IExtensionDescription } from '../../../platform/extensions/common/extensions.js';
import { ILogService } from '../../../platform/log/common/log.js';
import { CsrfRejectionReason, stripCsrfToken, verifyCsrfToken } from '../../../platform/uriHandler/common/uriHandlerCsrf.js';
import { CsrfSecretStore, resolveUriHandlerCsrfSecretFile } from '../../../platform/uriHandler/node/uriHandlerCsrf.js';
import type * as vscode from 'vscode';
import { IExtensionStoragePaths } from '../common/extHostStoragePaths.js';
import { IExtHostUriHandlerCsrf, IResolvedUriHandlerCsrf, resolveUriHandlerCsrf, UriHandlerCsrfDecision } from '../common/extHostUriHandlerCsrf.js';

const SECRET_ROTATION_CHECK_MS = 60 * 60 * 1000; // hourly; `rotateIfStale` only rewrites once a secret crosses its 24h age

/**
 * Node CSRF service: owns the config, secret store, rotation timer and verification for protected
 * `vscode.UriHandler` registrations. `ExtHostUrls` just calls `initialize`/`handle`.
 *
 * CSRF enforcement is POSIX-only for now: it relies on file-permission checks (owner/group-only), and
 * the Windows ACL equivalent isn't implemented yet. On Windows a protected handler follows its
 * explicit `unsupportedPlatforms` policy, and a warning is logged either way.
 */
export class NodeExtHostUriHandlerCsrf implements IExtHostUriHandlerCsrf {
	declare readonly _serviceBrand: undefined;

	private readonly store: CsrfSecretStore;
	// `secretFile` is absent when CSRF can't be enforced here (Windows); those entries are skipped by
	// rotation and retain the policy needed to strip reserved parameters or fail closed.
	private readonly configs = new Map<string, { readonly secretFile?: URI; readonly unprotectedPaths: ReadonlySet<string>; readonly unsupportedPlatforms: 'allow' | 'reject' }>();
	private rotationTimer: ReturnType<typeof setInterval> | undefined;

	constructor(
		@IExtensionStoragePaths private readonly storagePaths: IExtensionStoragePaths,
		@ILogService private readonly logService: ILogService,
	) {
		this.store = new CsrfSecretStore(logService);
	}

	initialize(extension: IExtensionDescription, options?: vscode.UriHandlerOptions): IDisposable {
		const resolved = resolveUriHandlerCsrf(extension, options);
		if (!resolved) {
			return Disposable.None;
		}

		const key = ExtensionIdentifier.toKey(extension.identifier);

		if (process.platform === 'win32') {
			// Unsupported on Windows for now — trusting the secret needs an ACL check (fs mode bits are
			// unreliable there) that isn't implemented yet. Record the policy so protected URIs have their
			// reserved parameters stripped and fail-closed handlers can reject non-exempt deeplinks rather
			// than silently trusting them.
			this.logService.warn(`[uri-csrf] CSRF protection for ${extension.identifier.value} is not enforced on Windows; deeplinks are ${resolved.unsupportedPlatforms === 'reject' ? 'rejected' : 'dispatched without verification'}.`);
			this.configs.set(key, { unprotectedPaths: resolved.unprotectedPaths, unsupportedPlatforms: resolved.unsupportedPlatforms });
			return toDisposable(() => this.configs.delete(key));
		}

		const secretFile = this.secretFileFor(extension, resolved);
		this.configs.set(key, { secretFile, unprotectedPaths: resolved.unprotectedPaths, unsupportedPlatforms: resolved.unsupportedPlatforms });

		// Materialize the secret now so a companion tool can read it and sign the first link before any
		// deeplink arrives (getSecret creates it if absent).
		this.store.getSecret(secretFile).catch(err => onUnexpectedError(err));
		this.ensureRotationTimer();

		return toDisposable(() => {
			this.configs.delete(key);
			if (![...this.configs.values()].some(config => config.secretFile)) {
				this.stopRotationTimer();
			}
		});
	}

	async handle(extension: IExtensionDescription, uri: URI): Promise<UriHandlerCsrfDecision> {
		const config = this.configs.get(ExtensionIdentifier.toKey(extension.identifier));
		if (!config) {
			return { kind: 'dispatch', uri: stripCsrfToken(uri) }; // reserved parameters are never extension input
		}
		if (config.unprotectedPaths.has(uri.path)) {
			return { kind: 'dispatch', uri: stripCsrfToken(uri) }; // exempt path (e.g. an OAuth callback)
		}
		if (!config.secretFile) {
			// Unenforceable here (Windows): honor the configured fallback without leaking reserved params.
			if (config.unsupportedPlatforms === 'allow') {
				return { kind: 'dispatch', uri: stripCsrfToken(uri) };
			}
			this.logService.warn(`[uri-csrf] rejected URI for ${extension.identifier.value} (path: ${uri.path}, reason: unenforceable-platform)`);
			return { kind: 'reject' };
		}
		if (await this.verify(config.secretFile, uri)) {
			return { kind: 'dispatch', uri: stripCsrfToken(uri) };
		}
		this.logService.warn(`[uri-csrf] rejected URI for ${extension.identifier.value} (path: ${uri.path})`);
		return { kind: 'reject' };
	}

	private async verify(secretFile: URI, uri: URI): Promise<boolean> {
		const now = Date.now();
		let secret: Uint8Array | undefined;
		try {
			secret = await this.store.getSecret(secretFile);
		} catch (err) {
			onUnexpectedError(err);
			secret = undefined;
		}

		let result = await verifyCsrfToken(secret, uri.authority, uri.path, uri.query, now, uri.fragment);
		if (!result.ok && result.reason === CsrfRejectionReason.InvalidSignature) {
			// Fall back to the just-rotated-out secret, so a link signed right before a rotation (e.g.
			// the deeplink that woke VS Code) still verifies.
			const previous = await this.store.getPreviousSecret(secretFile).catch(() => undefined);
			if (previous) {
				result = await verifyCsrfToken(previous, uri.authority, uri.path, uri.query, now, uri.fragment);
			}
		}
		return result.ok;
	}

	private secretFileFor(extension: IExtensionDescription, resolved: IResolvedUriHandlerCsrf): URI {
		return resolveUriHandlerCsrfSecretFile(this.storagePaths.globalValue(extension), resolved, this.logService);
	}

	// Rotate protected extensions' secrets on a timer, off the verification path — `getSecret` never
	// rotates, so a deeplink is always checked against the secret it was signed with.
	private ensureRotationTimer(): void {
		if (this.rotationTimer) {
			return;
		}
		this.rotateStaleSecrets(); // catch up now (e.g. a secret left stale from a previous session)
		this.rotationTimer = setInterval(() => this.rotateStaleSecrets(), SECRET_ROTATION_CHECK_MS);
		(this.rotationTimer as { unref?(): void }).unref?.();
	}

	private stopRotationTimer(): void {
		if (this.rotationTimer) {
			clearInterval(this.rotationTimer);
			this.rotationTimer = undefined;
		}
	}

	private rotateStaleSecrets(): void {
		for (const config of this.configs.values()) {
			if (config.secretFile) {
				this.store.rotateIfStale(config.secretFile).catch(err => onUnexpectedError(err));
			}
		}
	}

	dispose(): void {
		this.stopRotationTimer();
		this.configs.clear();
	}
}
