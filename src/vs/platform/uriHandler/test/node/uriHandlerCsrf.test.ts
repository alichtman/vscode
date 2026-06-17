/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { promises as fs } from 'fs';
import { tmpdir } from 'os';
import { join } from '../../../../base/common/path.js';
import { URI } from '../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import { IExtension } from '../../../extensions/common/extensions.js';
import { NullLogService } from '../../../log/common/log.js';
import { verifyCsrfToken } from '../../common/uriHandlerCsrf.js';
import { CsrfSecretStore, signInstalledExtensionUri } from '../../node/uriHandlerCsrf.js';

suite('URI handler CSRF CLI signer', () => {
	ensureNoDisposablesAreLeakedInTestSuite();

	let dir: string;

	setup(async () => {
		dir = await fs.mkdtemp(join(tmpdir(), 'uri-csrf-cli-signer-'));
	});

	teardown(async () => {
		await fs.rm(dir, { recursive: true, force: true });
	});

	function extension(csrfProtection: object | undefined): IExtension {
		return {
			identifier: { id: 'test.ext' },
			manifest: { contributes: { uriHandler: { csrfProtection } } },
		} as unknown as IExtension;
	}

	test('provisions the secret and signs path, query, and fragment', async () => {
		const logService = new NullLogService();
		const signedValue = await signInstalledExtensionUri(
			'vscode://test.ext/run?task=build#trusted-fragment',
			'vscode',
			[extension({ unsupportedPlatforms: 'reject' })],
			URI.file(dir),
			logService,
		);

		const signed = URI.parse(signedValue);
		const secretFile = URI.file(join(dir, 'test.ext', 'uri-csrf.secret'));
		const secret = await new CsrfSecretStore(logService).getSecret(secretFile);
		assert.ok(secret);
		assert.deepStrictEqual(await verifyCsrfToken(secret, signed.path, signed.query, Date.now(), signed.fragment), { ok: true });
	});

	test('rejects an extension without an explicit unsupported-platform policy', async () => {
		await assert.rejects(
			signInstalledExtensionUri('vscode://test.ext/run', 'vscode', [extension({})], URI.file(dir), new NullLogService()),
			/invalid contributes\.uriHandler\.csrfProtection declaration/,
		);
	});
});
