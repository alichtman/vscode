/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { URI } from '../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import {
	canonicalize,
	computeToken,
	CSRF_TOKEN_PARAM,
	CSRF_TS_PARAM,
	CsrfRejectionReason,
	extractToken,
	MAX_TOKEN_AGE_MS,
	MAX_TOKEN_FUTURE_SKEW_MS,
	stripCsrfToken,
	timingSafeEqual,
	verifyCsrfToken,
} from '../../../../platform/uriHandler/common/uriHandlerCsrf.js';

suite('ExtHostUriHandlerCsrf', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	const secret = new TextEncoder().encode('a-very-secret-32-byte-test-value');
	const AUTHORITY = 'test.ext';
	const PATH = '/start';
	const NOW = 1_700_000_000_000;

	/** Build the query string a legitimate signer would produce (timestamp included in the signed message). */
	async function sign(path: string, params: Record<string, string>, ts: number = NOW): Promise<string> {
		const all: Record<string, string> = { ...params, [CSRF_TS_PARAM]: String(ts) };
		const base = Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
		const token = await computeToken(secret, AUTHORITY, path, base);
		return `${base}&${CSRF_TOKEN_PARAM}=${token}`;
	}

	test('canonicalize binds the path, is order/encoding-independent, and excludes the token', () => {
		const a = canonicalize(AUTHORITY, '/start', 'program=%2Fbin%2Fsh&request=launch');
		const b = canonicalize(AUTHORITY, '/start', 'request=launch&program=/bin/sh');
		assert.strictEqual(a, b);
		assert.strictEqual(a, 'test.ext\n%2Fstart\n\nprogram=%2Fbin%2Fsh\nrequest=launch');

		// Different routes produce different canonical messages even with identical params.
		assert.notStrictEqual(canonicalize(AUTHORITY, '/start', 'program=/bin/sh'), canonicalize(AUTHORITY, '/run', 'program=/bin/sh'));

		// A shared secret cannot move a signed route from one extension to another.
		assert.notStrictEqual(canonicalize(AUTHORITY, '/start', 'program=/bin/sh'), canonicalize('other.ext', '/start', 'program=/bin/sh'));
		assert.strictEqual(canonicalize('TEST.EXT', '/start', 'program=/bin/sh'), canonicalize(AUTHORITY, '/start', 'program=/bin/sh'));

		// The reserved token param must never participate in the signed message.
		assert.strictEqual(canonicalize(AUTHORITY, '/start', `program=/bin/sh&${CSRF_TOKEN_PARAM}=deadbeef`), 'test.ext\n%2Fstart\n\nprogram=%2Fbin%2Fsh');
	});

	test('serialization is injective: a value with delimiters cannot mimic separate params', () => {
		// A single param whose value contains '\n' and '=' must not canonicalize to the same message
		// as two distinct params — otherwise a token could be replayed across different param sets.
		const oneParamWithDelimiters = canonicalize(AUTHORITY, '/x', `a=${encodeURIComponent('b\nc=d')}`);
		const twoParams = canonicalize(AUTHORITY, '/x', 'a=b&c=d');
		assert.notStrictEqual(oneParamWithDelimiters, twoParams);
	});

	test('extractToken / stripCsrfToken (strips both reserved params)', () => {
		assert.strictEqual(extractToken('a=1&b=2'), undefined);
		assert.strictEqual(extractToken(`a=1&${CSRF_TOKEN_PARAM}=abc&b=2`), 'abc');

		const stripped = stripCsrfToken(URI.parse(`vscode://ext.id/start?a=1&${CSRF_TOKEN_PARAM}=abc&${CSRF_TS_PARAM}=123&b=2`));
		assert.strictEqual(stripped.query, 'a=1&b=2');
		assert.strictEqual(extractToken(stripped.query), undefined);
	});

	test('timingSafeEqual', () => {
		assert.strictEqual(timingSafeEqual('abc', 'abc'), true);
		assert.strictEqual(timingSafeEqual('abc', 'abd'), false);
		assert.strictEqual(timingSafeEqual('abc', 'abcd'), false);
		assert.strictEqual(timingSafeEqual('', ''), true);
	});

	test('a correctly signed, fresh link verifies', async () => {
		const query = await sign(PATH, { program: '/bin/sh', request: 'launch' });
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, query, NOW);
		assert.deepStrictEqual(result, { ok: true });
	});

	test('tampering with any param invalidates the signature', async () => {
		const signed = await sign(PATH, { program: '/bin/sh', request: 'launch' });
		const token = extractToken(signed)!;
		const tampered = `program=${encodeURIComponent('/bin/evil')}&request=launch&${CSRF_TS_PARAM}=${NOW}&${CSRF_TOKEN_PARAM}=${token}`;
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, tampered, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.InvalidSignature });
	});

	test('a token minted for one route does not validate against another (path binding)', async () => {
		const signed = await sign('/start', { program: '/bin/sh' });
		// Replay the exact same params + token against a different protected route.
		const result = await verifyCsrfToken(secret, AUTHORITY, '/run', signed, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.InvalidSignature });
	});

	test('a token minted for one extension does not validate for another sharing the same secret', async () => {
		const signed = await sign(PATH, { program: '/bin/sh' });
		const result = await verifyCsrfToken(secret, 'other.ext', PATH, signed, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.InvalidSignature });
	});

	test('a token minted for one fragment does not validate against another', async () => {
		const base = `program=%2Fbin%2Fsh&${CSRF_TS_PARAM}=${NOW}`;
		const token = await computeToken(secret, AUTHORITY, PATH, base, 'trusted');
		const signed = `${base}&${CSRF_TOKEN_PARAM}=${token}`;
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, signed, NOW, 'tampered');
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.InvalidSignature });
	});

	test('missing token is rejected', async () => {
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, `program=/bin/sh&${CSRF_TS_PARAM}=${NOW}`, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.Missing });
	});

	test('no secret fails closed (even with a token present)', async () => {
		const signed = await sign(PATH, { program: '/bin/sh' });
		const result = await verifyCsrfToken(undefined, AUTHORITY, PATH, signed, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.NoSecret });
	});

	test('a link older than the max age is rejected as expired', async () => {
		const signed = await sign(PATH, { program: '/bin/sh' }, NOW - MAX_TOKEN_AGE_MS - 1);
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, signed, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.Expired });
	});

	test('a validly-signed link with no timestamp is rejected as expired', async () => {
		const base = 'program=%2Fbin%2Fsh';
		const token = await computeToken(secret, AUTHORITY, PATH, base);
		const signed = `${base}&${CSRF_TOKEN_PARAM}=${token}`;
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, signed, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.Expired });
	});

	test('a link dated beyond the future clock-skew allowance is rejected as expired', async () => {
		const signed = await sign(PATH, { program: '/bin/sh' }, NOW + MAX_TOKEN_FUTURE_SKEW_MS + 1);
		const result = await verifyCsrfToken(secret, AUTHORITY, PATH, signed, NOW);
		assert.deepStrictEqual(result, { ok: false, reason: CsrfRejectionReason.Expired });
	});
});
