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

const CSRF_TOKEN_PARAMS = new Set([CSRF_TOKEN_PARAM]);
const CSRF_RESERVED_PARAMS = new Set([CSRF_TOKEN_PARAM, CSRF_TS_PARAM]);

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
	if (malformed) {
		return malformedManifestPolicy();
	}
	return {
		secretFileSpec: isString(manifest.secretFile) ? manifest.secretFile : undefined,
		unprotectedPaths: new Set(Array.isArray(manifest.unprotectedPaths) && manifest.unprotectedPaths.every(isString) ? manifest.unprotectedPaths : []),
		unsupportedPlatforms: manifest.unsupportedPlatforms === 'allow' ? 'allow' : 'reject',
		malformed: false,
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

function isReservedQueryParam(part: string, reserved: ReadonlySet<string>): boolean {
	const eq = part.indexOf('=');
	return reserved.has(safeDecode(eq === -1 ? part : part.slice(0, eq)));
}

/**
 * Canonical form shared by the CLI signer and extension-host verifier. It binds the token to the
 * normalized extension authority, URI path, fragment, and the *exact* query serialization that
 * `handleUri` is about to receive: only the token parameter itself is removed, and nothing else is
 * reordered, deduplicated, or re-encoded. Reordering parameters, swapping two duplicates of the
 * same key, or rewriting `a` as `a=` therefore all yield a different message and a different HMAC.
 *
 * Note that `query` is the query as `URI` exposes it, i.e. already percent-decoded once. Signers
 * must canonicalize that same representation rather than the on-the-wire spelling.
 */
export function canonicalize(authority: string, path: string, query: string, fragment: string = ''): string {
	const signedQuery = query.split('&').filter(part => !isReservedQueryParam(part, CSRF_TOKEN_PARAMS)).join('&');
	return [encodeURIComponent(authority.toLowerCase()), encodeURIComponent(path), encodeURIComponent(fragment), encodeURIComponent(signedQuery)].join('\n');
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
	const kept = uri.query.split('&').filter(part => !!part && !isReservedQueryParam(part, CSRF_RESERVED_PARAMS));
	return uri.with({ query: kept.join('&') });
}

function toHex(bytes: Uint8Array): string {
	let out = '';
	for (let i = 0; i < bytes.length; i++) {
		out += bytes[i].toString(16).padStart(2, '0');
	}
	return out;
}

export async function computeToken(secret: Uint8Array, authority: string, path: string, query: string, fragment: string = ''): Promise<string> {
	const key = await crypto.subtle.importKey('raw', secret as unknown as ArrayBufferView<ArrayBuffer>, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const message = new TextEncoder().encode(canonicalize(authority, path, query, fragment));
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

/**
 * Verify the token carried by `query` against `secret`.
 *
 * `maxTokenTimestamp` is the newest signing timestamp `secret` may vouch for. It is what stops a
 * rotated-out key from minting fresh links: the retired key stays usable for the links that were
 * genuinely signed before it was retired, and nothing newer.
 */
export async function verifyCsrfToken(secret: Uint8Array | undefined, authority: string, path: string, query: string, now: number, fragment: string = '', maxTokenTimestamp: number = Number.POSITIVE_INFINITY): Promise<CsrfVerifyResult> {
	const claimed = extractToken(query);
	if (claimed === undefined) {
		return { ok: false, reason: CsrfRejectionReason.Missing };
	}
	if (!secret) {
		return { ok: false, reason: CsrfRejectionReason.NoSecret };
	}
	const expected = await computeToken(secret, authority, path, query, fragment);
	if (!timingSafeEqual(expected, claimed)) {
		return { ok: false, reason: CsrfRejectionReason.InvalidSignature };
	}
	const ts = Number(extractParam(query, CSRF_TS_PARAM));
	if (!Number.isFinite(ts) || now - ts > MAX_TOKEN_AGE_MS || ts - now > MAX_TOKEN_FUTURE_SKEW_MS || ts > maxTokenTimestamp) {
		return { ok: false, reason: CsrfRejectionReason.Expired };
	}
	return { ok: true };
}

/** Add a fresh timestamp and HMAC token to an extension URI, replacing any reserved parameters. */
export async function signUri(secret: Uint8Array, uri: URI, now: number = Date.now()): Promise<URI> {
	const unsigned = stripCsrfToken(uri);
	const timestamp = `${encodeURIComponent(CSRF_TS_PARAM)}=${now}`;
	const query = unsigned.query ? `${unsigned.query}&${timestamp}` : timestamp;
	const token = await computeToken(secret, unsigned.authority, unsigned.path, query, unsigned.fragment);
	return unsigned.with({ query: `${query}&${encodeURIComponent(CSRF_TOKEN_PARAM)}=${token}` });
}
