/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { execFile } from 'child_process';
import { promises as fs } from 'fs';
import { tmpdir } from 'os';
import { join } from '../../../../base/common/path.js';
import { promisify } from 'util';
import type * as vscode from 'vscode';
import { URI } from '../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import { ExtensionIdentifier, IExtensionDescription } from '../../../../platform/extensions/common/extensions.js';
import { NullLogService } from '../../../../platform/log/common/log.js';
import { CsrfSecretStore } from '../../../../platform/uriHandler/node/uriHandlerCsrf.js';
import { ExtHostUrls } from '../../common/extHostUrls.js';
import { IExtensionStoragePaths } from '../../common/extHostStoragePaths.js';
import { NodeExtHostUriHandlerCsrf } from '../../node/extHostUriHandlerCsrf.js';
import { SingleProxyRPCProtocol } from '../common/testRPCProtocol.js';

const execFileAsync = promisify(execFile);

// A standalone companion-tool signer — pure Node, zero VS Code dependencies, exactly as an extension
// author would ship it (see docs/uri-handler-csrf-protection.md). Run as its own process:
//   node sign.cjs <secretFile> <extensionId> <uriPath> <key=value...>  ->  prints a signed vscode:// link
const SIGNER_CLI = `
'use strict';
const { createHmac } = require('crypto');
const { readFileSync } = require('fs');
const [, , secretFile, extensionId, uriPath, ...kv] = process.argv;
const params = kv.map(s => { const i = s.indexOf('='); return [s.slice(0, i), s.slice(i + 1)]; });
params.push(['vscode-csrf-ts', String(Date.now())]);
const secret = Buffer.from(JSON.parse(readFileSync(secretFile, 'utf8')).secret, 'base64');
// The signature covers the query exactly as the handler will receive it: same order, same
// duplicates, and already percent-decoded, because VS Code decodes the query once when it parses
// the link. Only the token itself is left out of the signed message.
const decodedQuery = params.map(([k, v]) => k + '=' + v).join('&');
const canonical = [extensionId.toLowerCase(), uriPath, '', decodedQuery].map(encodeURIComponent).join('\\n');
const token = createHmac('sha256', secret).update(canonical).digest('hex');
const wireQuery = params.map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v))
	.concat('vscode-csrf-token=' + token)
	.join('&');
process.stdout.write('vscode://' + extensionId + uriPath + '?' + wireQuery);
`;

async function waitForFile(path: string): Promise<void> {
	for (let i = 0; i < 200; i++) {
		try {
			await fs.access(path);
			return;
		} catch {
			await new Promise(resolve => setTimeout(resolve, 5));
		}
	}
	throw new Error(`secret file was not created: ${path}`);
}

suite('ExtHostUrls CSRF — external CLI signer interop', () => {

	const disposables = ensureNoDisposablesAreLeakedInTestSuite();

	let dir: string;
	let signerPath: string;
	let secretPath: string;
	let extHostUrls: ExtHostUrls;
	let handle: number;
	let received: vscode.Uri | undefined;
	let rejections: number;

	setup(async () => {
		dir = await fs.mkdtemp(join(tmpdir(), 'uri-csrf-cli-'));
		signerPath = join(dir, 'sign.cjs');
		secretPath = join(dir, 'uri-csrf.secret');
		await fs.writeFile(signerPath, SIGNER_CLI);
		received = undefined;
		rejections = 0;

		const mainThread = {
			$registerUriHandler: (h: number) => { handle = h; },
			$unregisterUriHandler: () => { },
			$createAppUri: async (u: unknown) => u,
			$notifyCsrfDeeplinkRejection: () => { rejections++; },
		};
		const storagePaths = { globalValue: () => URI.file(dir) } as unknown as IExtensionStoragePaths;
		const log = new NullLogService();
		extHostUrls = new ExtHostUrls(SingleProxyRPCProtocol(mainThread), new NodeExtHostUriHandlerCsrf(storagePaths, log));

		disposables.add(extHostUrls.registerUriHandler(
			{ identifier: new ExtensionIdentifier('test.ext'), name: 'ext', displayName: 'Test Ext', contributes: { uriHandler: { csrfProtection: { unsupportedPlatforms: 'reject' } } } } as unknown as IExtensionDescription,
			{ handleUri: uri => { received = uri; } },
		));

		// Registration materializes the secret (no manual pre-creation); wait for that to land before
		// the external CLI reads it.
		await waitForFile(secretPath);
	});

	teardown(async () => {
		await fs.rm(dir, { recursive: true, force: true });
	});

	/** Generate a deeplink by running the standalone signer in its own `node` process. */
	async function signWithExternalCli(secretFile: string, uriPath: string, ...params: string[]): Promise<string> {
		const { stdout } = await execFileAsync(process.execPath, [signerPath, secretFile, 'test.ext', uriPath, ...params], {
			env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
		});
		return stdout.trim();
	}

	test('registering a protected handler materializes the secret (fresh install, no manual creation)', async () => {
		const stat = await fs.stat(secretPath);
		assert.ok(stat.isFile(), 'registration must create the secret so a companion tool can read it');
		if (process.platform !== 'win32') {
			assert.strictEqual(stat.mode & 0o777, 0o600, 'the materialized secret must be owner-only');
		}
	});

	test('a deeplink produced by an external CLI process is accepted end-to-end', async () => {
		const link = await signWithExternalCli(secretPath, '/start', 'program=/bin/sh', 'request=launch');
		assert.ok(link.startsWith('vscode://test.ext/start?'), `unexpected link: ${link}`);

		await extHostUrls.$handleExternalUri(handle, URI.parse(link).toJSON());

		assert.ok(received, 'a link signed by the external CLI must reach the handler');
		assert.strictEqual(received!.path, '/start');
		assert.strictEqual(rejections, 0);
	});

	test('an externally signed link keeps its parameter order and duplicates all the way to the handler', async () => {
		const link = await signWithExternalCli(secretPath, '/start', 'tag=b', 'tag=a', 'program=/bin/sh');

		await extHostUrls.$handleExternalUri(handle, URI.parse(link).toJSON());

		assert.strictEqual(received?.query, 'tag=b&tag=a&program=/bin/sh', 'the handler must see exactly what was signed');
		assert.strictEqual(rejections, 0);
	});

	test('reordering the duplicates of an externally signed link is rejected end-to-end', async () => {
		const link = await signWithExternalCli(secretPath, '/start', 'tag=b', 'tag=a');
		const reordered = link.replace('tag=b&tag=a', 'tag=a&tag=b');

		await extHostUrls.$handleExternalUri(handle, URI.parse(reordered).toJSON());

		assert.strictEqual(received, undefined, 'a handler that reads the first `tag` must not be steerable by reordering');
		assert.strictEqual(rejections, 1);
	});

	test('a tampered CLI deeplink is rejected end-to-end', async () => {
		const link = await signWithExternalCli(secretPath, '/start', 'program=/bin/sh');
		const tampered = link.replace('program=%2Fbin%2Fsh', 'program=%2Fbin%2Fevil');

		await extHostUrls.$handleExternalUri(handle, URI.parse(tampered).toJSON());

		assert.strictEqual(received, undefined, 'a tampered link must not reach the handler');
		assert.strictEqual(rejections, 1);
	});

	// --- Denial pipeline: a party WITHOUT the real secret (the web-attacker model) cannot get through ---

	test('a deeplink signed with a different secret (attacker has the recipe, not the key) is denied', async () => {
		// The attacker generates their own secret — they know the algorithm but cannot read VS Code's
		// owner-only secret file.
		const attackerSecret = join(dir, 'attacker.secret');
		await new CsrfSecretStore(new NullLogService()).getSecret(URI.file(attackerSecret));
		const link = await signWithExternalCli(attackerSecret, '/start', 'program=/bin/sh');

		await extHostUrls.$handleExternalUri(handle, URI.parse(link).toJSON());

		assert.strictEqual(received, undefined, 'a link signed with the wrong secret must be denied');
		assert.strictEqual(rejections, 1);
	});

	test('a raw unsigned deeplink (a web page) is denied', async () => {
		// Exactly what a malicious site can produce: a plain vscode:// navigation, no token.
		const raw = 'vscode://test.ext/start?program=%2Fbin%2Fsh';

		await extHostUrls.$handleExternalUri(handle, URI.parse(raw).toJSON());

		assert.strictEqual(received, undefined, 'an unsigned link must be denied');
		assert.strictEqual(rejections, 1);
	});
});
