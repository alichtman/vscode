/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { promises as fs } from 'fs';
import { tmpdir } from 'os';
import { join } from '../../../../base/common/path.js';
import type * as vscode from 'vscode';
import { URI } from '../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import { ExtensionIdentifier, IExtensionDescription } from '../../../../platform/extensions/common/extensions.js';
import { NullLogService } from '../../../../platform/log/common/log.js';
import { CsrfSecretStore } from '../../../../platform/uriHandler/node/uriHandlerCsrf.js';
import { ExtHostUrls } from '../../common/extHostUrls.js';
import { IExtensionStoragePaths } from '../../common/extHostStoragePaths.js';
import { UriHandlerUnsupportedPlatformPolicy } from '../../common/extHostTypes.js';
import { NodeExtHostUriHandlerCsrf } from '../../node/extHostUriHandlerCsrf.js';
import { computeToken, CSRF_TOKEN_PARAM, CSRF_TS_PARAM } from '../../../../platform/uriHandler/common/uriHandlerCsrf.js';
import { SingleProxyRPCProtocol } from '../common/testRPCProtocol.js';

/**
 * End-to-end of the extension-host dispatch path: real ExtHostUrls + real on-disk secret store,
 * driving $handleExternalUri with signed / forged / expired / exempt URIs.
 */
suite('ExtHostUrls CSRF dispatch (integration)', () => {

	const disposables = ensureNoDisposablesAreLeakedInTestSuite();

	let dir: string;
	let secret: Uint8Array;
	let extHostUrls: ExtHostUrls;
	let handle: number;
	let received: vscode.Uri | undefined;
	let rejections: string[];

	function makeExtension(csrfProtection: object | undefined): IExtensionDescription {
		return {
			identifier: new ExtensionIdentifier('test.ext'),
			name: 'ext',
			displayName: 'Test Ext',
			contributes: { uriHandler: { csrfProtection } },
		} as unknown as IExtensionDescription;
	}

	setup(async () => {
		dir = await fs.mkdtemp(join(tmpdir(), 'uri-csrf-e2e-'));
		received = undefined;
		rejections = [];

		const mainThread = {
			$registerUriHandler: (h: number) => { handle = h; },
			$unregisterUriHandler: () => { },
			$createAppUri: async (u: unknown) => u,
			$notifyCsrfDeeplinkRejection: (_id: ExtensionIdentifier, name: string) => { rejections.push(name); },
		};
		const storagePaths = { globalValue: () => URI.file(dir) } as unknown as IExtensionStoragePaths;
		const log = new NullLogService();
		extHostUrls = new ExtHostUrls(SingleProxyRPCProtocol(mainThread), new NodeExtHostUriHandlerCsrf(storagePaths, log));

		// Pre-create the secret (the same file the service will read) so we can sign valid links.
		secret = (await new CsrfSecretStore(log).getSecret(URI.file(join(dir, 'uri-csrf.secret'))))!;
	});

	teardown(async () => {
		await fs.rm(dir, { recursive: true, force: true });
	});

	function register(csrfProtection: object | undefined, options?: vscode.UriHandlerOptions): void {
		disposables.add(extHostUrls.registerUriHandler(makeExtension(csrfProtection), { handleUri: uri => { received = uri; } }, options));
	}

	async function signedUri(path: string, params: Record<string, string>, ts: number = Date.now()): Promise<URI> {
		const all: Record<string, string> = { ...params, [CSRF_TS_PARAM]: String(ts) };
		const base = Object.entries(all).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');
		const token = await computeToken(secret, 'test.ext', path, base);
		return URI.parse(`vscode://test.ext${path}?${base}&${CSRF_TOKEN_PARAM}=${token}`);
	}

	test('a valid signed link reaches the handler with CSRF params stripped', async () => {
		register({ unsupportedPlatforms: 'reject' });
		const uri = await signedUri('/start', { program: '/bin/sh' });
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.ok(received, 'handler should have been invoked');
		assert.strictEqual(received!.path, '/start');
		assert.strictEqual(received!.query, 'program=/bin/sh', 'token and timestamp must be stripped (query is URI-decoded)');
		assert.strictEqual(rejections.length, 0);
	});

	test('a forged link is rejected and never reaches the handler', async () => {
		register({ unsupportedPlatforms: 'reject' });
		const uri = URI.parse(`vscode://test.ext/start?program=%2Fbin%2Fsh&${CSRF_TS_PARAM}=${Date.now()}&${CSRF_TOKEN_PARAM}=deadbeef`);
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.strictEqual(received, undefined, 'a forged link must not reach the handler');
		assert.deepStrictEqual(rejections, ['Test Ext']);
	});

	test('a link cannot be moved to another extension even when the secret is shared', async () => {
		register({ unsupportedPlatforms: 'reject' });
		const uri = (await signedUri('/start', { program: '/bin/sh' })).with({ authority: 'other.ext' });
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.strictEqual(received, undefined);
		assert.deepStrictEqual(rejections, ['Test Ext']);
	});

	test('an expired link is rejected', async () => {
		register({ unsupportedPlatforms: 'reject' });
		const uri = await signedUri('/start', { program: '/bin/sh' }, Date.now() - 5 * 60 * 60 * 1000);
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.strictEqual(received, undefined, 'an expired link must not reach the handler');
		assert.deepStrictEqual(rejections, ['Test Ext']);
	});

	test('an exempt path is dispatched without a token', async () => {
		register({ unprotectedPaths: ['/did-authenticate'], unsupportedPlatforms: 'reject' });
		const uri = URI.parse('vscode://test.ext/did-authenticate?code=abc&vscode-csrf-token=unused&vscode-csrf-ts=123');
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.ok(received, 'exempt path should dispatch without a token');
		assert.strictEqual(received!.path, '/did-authenticate');
		assert.strictEqual(received!.query, 'code=abc');
		assert.strictEqual(rejections.length, 0);
	});

	test('an unprotected handler does not receive globally reserved parameters', async () => {
		register(undefined);
		const uri = URI.parse('vscode://test.ext/start?x=1&vscode-csrf-token=extension-value&vscode-csrf-ts=123');
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.ok(received);
		assert.strictEqual(received.query, 'x=1');
		assert.strictEqual(rejections.length, 0);
	});

	test('a relative manifest secret path falls back to the global-storage secret', async () => {
		register({ secretFile: 'relative.secret', unsupportedPlatforms: 'reject' });
		const uri = await signedUri('/start', { program: '/bin/sh' });
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.ok(received, 'a link signed with the default secret should be accepted');
		assert.strictEqual(rejections.length, 0);
	});

	test('a non-file runtime secret URI falls back to the global-storage secret', async () => {
		register(undefined, { csrfProtection: { secretFile: URI.parse('https://example.com/secret'), unsupportedPlatforms: UriHandlerUnsupportedPlatformPolicy.Reject } });
		const uri = await signedUri('/start', { program: '/bin/sh' });
		await extHostUrls.$handleExternalUri(handle, uri.toJSON());

		assert.ok(received, 'a link signed with the default secret should be accepted');
		assert.strictEqual(rejections.length, 0);
	});

	test('a link signed with the previous secret still verifies right after a (wake-up) rotation', async () => {
		register({ unsupportedPlatforms: 'reject' });
		const uri = await signedUri('/start', { program: '/bin/sh' }); // signed with the current secret

		// Simulate waking after >24h: age the secret and rotate it out (old becomes "previous").
		const secretPath = join(dir, 'uri-csrf.secret');
		const parsed = JSON.parse(await fs.readFile(secretPath, 'utf8'));
		parsed.createdAt = Date.now() - 25 * 60 * 60 * 1000;
		await fs.writeFile(secretPath, JSON.stringify(parsed), { mode: 0o600 });
		await new CsrfSecretStore(new NullLogService()).rotateIfStale(URI.file(secretPath));

		await extHostUrls.$handleExternalUri(handle, uri.toJSON());
		assert.ok(received, 'a link signed with the previous secret must still verify after rotation');
		assert.strictEqual(rejections.length, 0);
	});
});
