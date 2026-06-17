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
import { NullLogService } from '../../../../platform/log/common/log.js';
import { CsrfSecretStore } from '../../../../platform/uriHandler/node/uriHandlerCsrf.js';
import { computeToken, CSRF_TOKEN_PARAM, CSRF_TS_PARAM, verifyCsrfToken } from '../../../../platform/uriHandler/common/uriHandlerCsrf.js';

suite('CsrfSecretStore (integration)', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	const isWindows = process.platform === 'win32';
	let dir: string;
	let store: CsrfSecretStore;

	setup(async () => {
		dir = await fs.mkdtemp(join(tmpdir(), 'uri-csrf-'));
		store = new CsrfSecretStore(new NullLogService());
	});

	teardown(async () => {
		await fs.rm(dir, { recursive: true, force: true });
	});

	function secretUri(name = 'uri-csrf.secret'): URI {
		return URI.file(join(dir, name));
	}

	test('creates an owner-only secret of sufficient length', async () => {
		const file = secretUri();
		const secret = await store.getSecret(file);

		assert.ok(secret && secret.length >= 32, 'secret should be at least 32 bytes');
		const stat = await fs.stat(file.fsPath);
		if (!isWindows) {
			assert.strictEqual(stat.mode & 0o777, 0o600, 'secret file should be created mode 0600');
		}
	});

	async function ageSecret(file: URI): Promise<void> {
		const parsed = JSON.parse(await fs.readFile(file.fsPath, 'utf8'));
		parsed.createdAt = Date.now() - 25 * 60 * 60 * 1000;
		await fs.writeFile(file.fsPath, JSON.stringify(parsed), { mode: 0o600 });
	}

	test('getSecret is read-only: it returns the same secret even when stale (never fails the first deeplink)', async () => {
		const file = secretUri();
		const first = await store.getSecret(file);
		await ageSecret(file);
		const second = await store.getSecret(file);
		assert.deepStrictEqual(Array.from(second!), Array.from(first!), 'getSecret must not rotate');
	});

	test('rotateIfStale rotates a secret past the rotation window', async () => {
		const file = secretUri();
		const first = await store.getSecret(file);
		await ageSecret(file);
		await store.rotateIfStale(file);
		const second = await store.getSecret(file);
		assert.notDeepStrictEqual(Array.from(second!), Array.from(first!), 'a stale secret must be rotated');
	});

	test('rotateIfStale leaves a fresh secret unchanged', async () => {
		const file = secretUri();
		const first = await store.getSecret(file);
		await store.rotateIfStale(file);
		const second = await store.getSecret(file);
		assert.deepStrictEqual(Array.from(second!), Array.from(first!), 'a fresh secret must not be rotated');
	});

	test('no previous secret before the first rotation', async () => {
		const file = secretUri();
		await store.getSecret(file);
		assert.strictEqual(await store.getPreviousSecret(file), undefined);
	});

	test('rotation retains the prior secret as the previous secret (one cycle of grace)', async () => {
		const file = secretUri();
		const first = await store.getSecret(file);
		await ageSecret(file);
		await store.rotateIfStale(file);

		const current = await store.getSecret(file);
		const previous = await store.getPreviousSecret(file);
		assert.notDeepStrictEqual(Array.from(current!), Array.from(first!), 'the secret should have rotated');
		assert.deepStrictEqual(Array.from(previous!), Array.from(first!), 'the prior secret should be retained as previous');
	});

	test('end-to-end: a link signed with the stored secret verifies, and tampering is rejected', async () => {
		const secret = (await store.getSecret(secretUri()))!;
		const path = '/start';
		const now = 1_700_000_000_000;
		const base = `program=%2Fbin%2Fsh&request=launch&${CSRF_TS_PARAM}=${now}`;

		const token = await computeToken(secret, path, base);
		const signed = `${base}&${CSRF_TOKEN_PARAM}=${token}`;
		assert.deepStrictEqual(await verifyCsrfToken(secret, path, signed, now), { ok: true });

		const tampered = `program=%2Fbin%2Fevil&request=launch&${CSRF_TS_PARAM}=${now}&${CSRF_TOKEN_PARAM}=${token}`;
		assert.strictEqual((await verifyCsrfToken(secret, path, tampered, now)).ok, false);
	});

	(isWindows ? test.skip : test)('rejects a world-writable secret (POSIX)', async () => {
		const file = secretUri();
		await store.getSecret(file); // create it 0600
		await fs.chmod(file.fsPath, 0o606); // make it world-writable

		const secret = await store.getSecret(file);
		assert.strictEqual(secret, undefined, 'a world-writable secret must not be trusted');
	});

	(isWindows ? test.skip : test)('rejects a world-readable secret (POSIX)', async () => {
		const file = secretUri();
		await store.getSecret(file); // create it 0600
		await fs.chmod(file.fsPath, 0o604); // make it world-readable

		const secret = await store.getSecret(file);
		assert.strictEqual(secret, undefined, 'a world-readable secret must not be trusted');
	});

	(isWindows ? test.skip : test)('trusts a group-readable/-writable secret (POSIX)', async () => {
		const file = secretUri();
		const created = await store.getSecret(file); // create it 0600
		await fs.chmod(file.fsPath, 0o660); // group read+write, no world access — allowed (e.g. a companion daemon)

		const secret = await store.getSecret(file);
		assert.ok(secret, 'a group-accessible (but not world-accessible) secret must be trusted');
		assert.deepStrictEqual(Array.from(secret!), Array.from(created!), 'the same secret should be returned');
	});
});
