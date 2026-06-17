/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { URI } from '../../../base/common/uri.js';
import { isString } from '../../../base/common/types.js';

/** Reserved query parameter carrying the HMAC token. */
export const CSRF_TOKEN_PARAM = 'vscode-csrf-token';

/** Reserved query parameter carrying the unix-ms timestamp the link was signed at. */
export const CSRF_TS_PARAM = 'vscode-csrf-ts';

/** Maximum age of a signed link. */
export const MAX_TOKEN_AGE_MS = 4 * 60 * 60 * 1000; // 4 hours

/** Maximum tolerated clock adjustment between signing and verification on the same machine. */
export const MAX_TOKEN_FUTURE_SKEW_MS = 5 * 60 * 1000; // 5 minutes

export interface IResolvedUriHandlerCsrfManifest {
	readonly secretFileSpec?: string;
	readonly unprotectedPaths: ReadonlySet<string>;
	readonly unsupportedPlatforms: 'allow' | 'reject';
	readonly malformed: boolean;
}

/** Resolve the untrusted `contributes.uriHandler` value without weakening malformed policy. */
export function resolveUriHandlerCsrfManifest(uriHandlerValue: unknown): IResolvedUriHandlerCsrfManifest | undefined {
	if (uriHandlerValue === undefined) {
		return undefined;
	}
	if (typeof uriHandlerValue !== 'object' || uriHandlerValue === null || Array.isArray(uriHandlerValue)) {
		return malformedManifestPolicy();
	}
	const uriHandler = uriHandlerValue as Record<string, unknown>;
	if (Object.keys(uriHandler).some(key => key !== 'csrfProtection')) {
		return malformedManifestPolicy();
	}
	const manifestValue = uriHandler.csrfProtection;
	if (manifestValue === undefined) {
		return undefined;
	}
	if (typeof manifestValue !== 'object' || manifestValue === null || Array.isArray(manifestValue)) {
		return malformedManifestPolicy();
	}

	const manifest = manifestValue as Record<string, unknown>;
	const knownProperties = new Set(['secretFile', 'unprotectedPaths', 'unsupportedPlatforms']);
	const hasUnknownProperty = Object.keys(manifest).some(key => !knownProperties.has(key));
	const hasInvalidSecretFile = manifest.secretFile !== undefined && !isString(manifest.secretFile);
	const hasInvalidUnprotectedPaths = manifest.unprotectedPaths !== undefined
		&& (!Array.isArray(manifest.unprotectedPaths) || !manifest.unprotectedPaths.every(isString));
	const hasInvalidUnsupportedPlatforms = manifest.unsupportedPlatforms !== 'allow' && manifest.unsupportedPlatforms !== 'reject';
	const malformed = hasUnknownProperty || hasInvalidSecretFile || hasInvalidUnprotectedPaths || hasInvalidUnsupportedPlatforms;
	return {
		secretFileSpec: isString(manifest.secretFile) ? manifest.secretFile : undefined,
		unprotectedPaths: new Set(Array.isArray(manifest.unprotectedPaths) && manifest.unprotectedPaths.every(isString) ? manifest.unprotectedPaths : []),
		unsupportedPlatforms: manifest.unsupportedPlatforms === 'allow' && !malformed ? 'allow' : 'reject',
		malformed,
	};
}

function malformedManifestPolicy(): IResolvedUriHandlerCsrfManifest {
	return { unprotectedPaths: new Set(), unsupportedPlatforms: 'reject', malformed: true };
}

interface IQueryParam {
	readonly key: string;
	readonly value: string;
}

function parseQuery(query: string): IQueryParam[] {
	const params: IQueryParam[] = [];
	if (!query) {
		return params;
	}
	for (const part of query.split('&')) {
		if (!part) {
			continue;
		}
		const eq = part.indexOf('=');
		const rawKey = eq === -1 ? part : part.slice(0, eq);
		const rawValue = eq === -1 ? '' : part.slice(eq + 1);
		params.push({ key: safeDecode(rawKey), value: safeDecode(rawValue) });
	}
	return params;
}

function safeDecode(value: string): string {
	try {
		return decodeURIComponent(value);
	} catch {
		return value;
	}
}

/**
 * Canonical form shared by the CLI signer and extension-host verifier. It binds the token to the
 * URI path, fragment, and every non-reserved query parameter while normalizing query ordering and
 * percent encoding.
 */
export function canonicalize(path: string, query: string, fragment: string = ''): string {
	const params = parseQuery(query).filter(p => p.key !== CSRF_TOKEN_PARAM);
	params.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : a.value < b.value ? -1 : a.value > b.value ? 1 : 0);
	return [encodeURIComponent(path), encodeURIComponent(fragment), ...params.map(p => `${encodeURIComponent(p.key)}=${encodeURIComponent(p.value)}`)].join('\n');
}

function extractParam(query: string, key: string): string | undefined {
	for (const param of parseQuery(query)) {
		if (param.key === key) {
			return param.value;
		}
	}
	return undefined;
}

export function extractToken(query: string): string | undefined {
	return extractParam(query, CSRF_TOKEN_PARAM);
}

/** Remove every reserved CSRF query parameter before an extension URI handler sees the URI. */
export function stripCsrfToken(uri: URI): URI {
	if (!uri.query) {
		return uri;
	}
	const kept = uri.query.split('&').filter(part => {
		if (!part) {
			return false;
		}
		const eq = part.indexOf('=');
		const rawKey = safeDecode(eq === -1 ? part : part.slice(0, eq));
		return rawKey !== CSRF_TOKEN_PARAM && rawKey !== CSRF_TS_PARAM;
	});
	return uri.with({ query: kept.join('&') });
}

function toHex(bytes: Uint8Array): string {
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i].toString(16).padStart(2, '0');
	}
	return out;
}

export async function computeToken(secret: Uint8Array, path: string, query: string, fragment: string = ''): Promise<string> {
	const key = await crypto.subtle.importKey('raw', secret as unknown as ArrayBufferView<ArrayBuffer>, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const message = new TextEncoder().encode(canonicalize(path, query, fragment));
	const signature = await crypto.subtle.sign('HMAC', key, message as unknown as ArrayBufferView<ArrayBuffer>);
	return toHex(new Uint8Array(signature));
}

export function timingSafeEqual(a: string, b: string): boolean {
	const aBytes = new TextEncoder().encode(a);
	const bBytes = new TextEncoder().encode(b);
	const len = Math.max(aBytes.length, bBytes.length);
	let diff = aBytes.length ^ bBytes.length;
	for (let i = 0; i < len; i++) {
		diff |= (i < aBytes.length ? aBytes[i] : 0) ^ (i < bBytes.length ? bBytes[i] : 0);
	}
	return diff === 0;
}

export const enum CsrfRejectionReason {
	Missing = 'missing',
	NoSecret = 'no-secret',
	InvalidSignature = 'invalid-signature',
	Expired = 'expired',
}

export type CsrfVerifyResult = { readonly ok: true } | { readonly ok: false; readonly reason: CsrfRejectionReason };

export async function verifyCsrfToken(secret: Uint8Array | undefined, path: string, query: string, now: number, fragment: string = ''): Promise<CsrfVerifyResult> {
	const claimed = extractToken(query);
	if (claimed === undefined) {
		return { ok: false, reason: CsrfRejectionReason.Missing };
	}
	if (!secret) {
		return { ok: false, reason: CsrfRejectionReason.NoSecret };
	}
	const expected = await computeToken(secret, path, query, fragment);
	if (!timingSafeEqual(expected, claimed)) {
		return { ok: false, reason: CsrfRejectionReason.InvalidSignature };
	}
	const ts = Number(extractParam(query, CSRF_TS_PARAM));
	if (!Number.isFinite(ts) || now - ts > MAX_TOKEN_AGE_MS || ts - now > MAX_TOKEN_FUTURE_SKEW_MS) {
		return { ok: false, reason: CsrfRejectionReason.Expired };
	}
	return { ok: true };
}

/** Add a fresh timestamp and HMAC token to an extension URI, replacing any reserved parameters. */
export async function signUri(secret: Uint8Array, uri: URI, now: number = Date.now()): Promise<URI> {
	const unsigned = stripCsrfToken(uri);
	const timestamp = `${encodeURIComponent(CSRF_TS_PARAM)}=${now}`;
	const query = unsigned.query ? `${unsigned.query}&${timestamp}` : timestamp;
	const token = await computeToken(secret, unsigned.path, query, unsigned.fragment);
	return unsigned.with({ query: `${query}&${encodeURIComponent(CSRF_TOKEN_PARAM)}=${token}` });
}
