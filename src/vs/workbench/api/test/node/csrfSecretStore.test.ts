/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { spawn } from 'child_process';
import { promises as fs } from 'fs';
import { hostname, tmpdir } from 'os';
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

	test('concurrent creators all observe the same atomically-installed secret', async () => {
		const file = secretUri();
		const secrets = await Promise.all(Array.from({ length: 16 }, () => store.getSecret(file)));
		assert.ok(secrets.every(secret => secret !== undefined));
		assert.ok(secrets.every(secret => Buffer.from(secret!).equals(Buffer.from(secrets[0]!))));
	});

	test('does not overwrite an existing malformed secret file', async () => {
		const file = secretUri();
		await fs.writeFile(file.fsPath, '{ malformed', { mode: 0o600 });

		assert.strictEqual(await store.getSecret(file), undefined);
		assert.strictEqual(await fs.readFile(file.fsPath, 'utf8'), '{ malformed');
	});

	test('rejects a non-regular secret path', async () => {
		const file = secretUri();
		await fs.mkdir(file.fsPath);
		assert.strictEqual(await store.getSecret(file), undefined);
	});

	(isWindows ? test.skip : test)('rejects a symbolic-link secret without following it', async () => {
		const target = secretUri('target.secret');
		const file = secretUri();
		await fs.writeFile(target.fsPath, 'known contents', { mode: 0o600 });
		await fs.symlink(target.fsPath, file.fsPath);

		assert.strictEqual(await store.getSecret(file), undefined);
		assert.strictEqual(await fs.readFile(target.fsPath, 'utf8'), 'known contents');
	});

	(isWindows ? test.skip : test)('rejects a symbolic-link secret directory', async () => {
		const realDirectory = join(dir, 'real');
		const linkedDirectory = join(dir, 'linked');
		await fs.mkdir(realDirectory, { mode: 0o700 });
		await fs.symlink(realDirectory, linkedDirectory);

		assert.strictEqual(await store.getSecret(URI.file(join(linkedDirectory, 'uri-csrf.secret'))), undefined);
	});

	(isWindows ? test.skip : test)('rejects a secret under a non-sticky world-writable directory', async () => {
		const unsafeDirectory = join(dir, 'unsafe');
		await fs.mkdir(unsafeDirectory, { mode: 0o700 });
		await fs.chmod(unsafeDirectory, 0o777);

		assert.strictEqual(await store.getSecret(URI.file(join(unsafeDirectory, 'uri-csrf.secret'))), undefined);
	});

	(isWindows ? test.skip : test)('rejects a path through an unsafe ancestor even when the symlink resolves somewhere safe', async () => {
		// Resolving first would only ever see dir/safe/storage (0700) and trust it, but anyone can
		// repoint `link` because dir/unsafe is world-writable.
		const unsafeDirectory = join(dir, 'unsafe');
		const safeDirectory = join(dir, 'safe');
		await fs.mkdir(join(safeDirectory, 'storage'), { recursive: true, mode: 0o700 });
		await fs.mkdir(unsafeDirectory, { mode: 0o700 });
		await fs.symlink(safeDirectory, join(unsafeDirectory, 'link'));
		await fs.chmod(unsafeDirectory, 0o777);

		assert.strictEqual(await store.getSecret(URI.file(join(unsafeDirectory, 'link', 'storage', 'uri-csrf.secret'))), undefined);
	});

	(isWindows ? test.skip : test)('allows an intermediate symlink owned by this user (as macOS /var and /tmp require)', async () => {
		const realDirectory = join(dir, 'real');
		await fs.mkdir(realDirectory, { mode: 0o700 });
		await fs.symlink(realDirectory, join(dir, 'link'));

		const secret = await store.getSecret(URI.file(join(dir, 'link', 'storage', 'uri-csrf.secret')));
		assert.ok(secret, 'a trusted intermediate symlink must not block the secret');
		assert.ok((await fs.stat(join(realDirectory, 'storage', 'uri-csrf.secret'))).isFile());
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

	test('concurrent rotation keeps one coherent current/previous key pair', async () => {
		const file = secretUri();
		const first = await store.getSecret(file);
		await ageSecret(file);

		await Promise.all(Array.from({ length: 8 }, () => store.rotateIfStale(file)));

		const current = await store.getSecret(file);
		const previous = await store.getPreviousSecret(file);
		assert.notDeepStrictEqual(Array.from(current!), Array.from(first!));
		assert.deepStrictEqual(Array.from(previous!.secret), Array.from(first!));
	});

	/** The pid of a process that has certainly exited, so `kill(pid, 0)` reports it as gone. */
	async function exitedPid(): Promise<number> {
		const child = spawn(process.execPath, ['-e', ''], { stdio: 'ignore', env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' } });
		await new Promise<void>(resolve => child.once('exit', () => resolve()));
		return child.pid!;
	}

	/** Plant a rotation lock with the given metadata and back-date it by `ageMs`. */
	async function writeRotationLock(file: URI, metadata: object, ageMs: number): Promise<string> {
		const lockPath = `${file.fsPath}.lock`;
		await fs.writeFile(lockPath, JSON.stringify(metadata), { mode: 0o600 });
		const backdated = new Date(Date.now() - ageMs);
		await fs.utimes(lockPath, backdated, backdated);
		return lockPath;
	}

	/** A secret that is due for rotation, plus the bytes it currently holds. */
	async function staleSecret(): Promise<{ file: URI; original: Uint8Array }> {
		const file = secretUri();
		const original = (await store.getSecret(file))!;
		await ageSecret(file);
		return { file, original };
	}

	const ABANDONED_LOCK_AGE_MS = 10 * 60 * 1000; // past the store's 5-minute staleness threshold

	test('rotation reclaims a lock whose owning process is gone', async () => {
		const { file, original } = await staleSecret();
		const lockPath = await writeRotationLock(file, { pid: await exitedPid(), hostname: hostname(), createdAt: Date.now() - ABANDONED_LOCK_AGE_MS }, ABANDONED_LOCK_AGE_MS);

		await store.rotateIfStale(file);

		assert.notDeepStrictEqual(Array.from((await store.getSecret(file))!), Array.from(original), 'a lock left by a crashed window must not block rotation forever');
		await assert.rejects(fs.access(lockPath), 'the reclaimed lock must be released again');
	});

	test('rotation reclaims a stale lock whose metadata it cannot vouch for', async () => {
		const { file, original } = await staleSecret();
		// Written by another host (a shared home directory), so the local pid says nothing about it.
		await writeRotationLock(file, { pid: process.pid, hostname: `${hostname()}-elsewhere`, createdAt: Date.now() - ABANDONED_LOCK_AGE_MS }, ABANDONED_LOCK_AGE_MS);

		await store.rotateIfStale(file);

		assert.notDeepStrictEqual(Array.from((await store.getSecret(file))!), Array.from(original), 'an unattributable lock must be reclaimed once it is stale');
	});

	test('rotation never steals a lock held by a live process, however old', async () => {
		const { file, original } = await staleSecret();
		const lockPath = await writeRotationLock(file, { pid: process.pid, hostname: hostname(), createdAt: Date.now() - ABANDONED_LOCK_AGE_MS }, ABANDONED_LOCK_AGE_MS);

		await store.rotateIfStale(file);

		assert.deepStrictEqual(Array.from((await store.getSecret(file))!), Array.from(original), 'a live holder must keep the lock');
		await fs.access(lockPath); // throws if the lock was taken away
	});

	test('rotation waits behind a lock that is not yet stale', async () => {
		const { file, original } = await staleSecret();
		const lockPath = await writeRotationLock(file, {}, 0);

		await store.rotateIfStale(file);

		assert.deepStrictEqual(Array.from((await store.getSecret(file))!), Array.from(original), 'a fresh lock must be respected even with unreadable metadata');
		await fs.access(lockPath);
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
		assert.deepStrictEqual(Array.from(previous!.secret), Array.from(first!), 'the prior secret should be retained as previous');
		assert.ok(previous!.validBefore > Date.now(), 'the retired secret must carry the cutoff that bounds what it can vouch for');
	});

	test('a previous secret with no rotation cutoff is ignored, but the current secret is kept', async () => {
		const file = secretUri();
		await store.getSecret(file);
		await ageSecret(file);
		await store.rotateIfStale(file);

		// A secret file written before rotation cutoffs existed.
		const rotated = JSON.parse(await fs.readFile(file.fsPath, 'utf8'));
		const current = rotated.secret;
		delete rotated.previousSecretValidBefore;
		await fs.writeFile(file.fsPath, JSON.stringify(rotated), { mode: 0o600 });

		const secret = await store.getSecret(file);
		assert.strictEqual(Buffer.from(secret!).toString('base64'), current, 'the current secret must stay usable');
		assert.strictEqual(await store.getPreviousSecret(file), undefined, 'an unbounded previous secret must be ignored');
	});

	test('end-to-end: a link signed with the stored secret verifies, and tampering is rejected', async () => {
		const secret = (await store.getSecret(secretUri()))!;
		const path = '/start';
		const now = 1_700_000_000_000;
		const base = `program=%2Fbin%2Fsh&request=launch&${CSRF_TS_PARAM}=${now}`;

		const token = await computeToken(secret, 'test.ext', path, base);
		const signed = `${base}&${CSRF_TOKEN_PARAM}=${token}`;
		assert.deepStrictEqual(await verifyCsrfToken(secret, 'test.ext', path, signed, now), { ok: true });

		const tampered = `program=%2Fbin%2Fevil&request=launch&${CSRF_TS_PARAM}=${now}&${CSRF_TOKEN_PARAM}=${token}`;
		assert.strictEqual((await verifyCsrfToken(secret, 'test.ext', path, tampered, now)).ok, false);
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

	(isWindows ? test.skip : test)('rejects a group-writable secret the group cannot read (POSIX)', async () => {
		const file = secretUri();
		await store.getSecret(file); // create it 0600
		await fs.chmod(file.fsPath, 0o620); // the group can plant a secret but could never legitimately sign with one

		assert.strictEqual(await store.getSecret(file), undefined, 'a write-only-for-group secret must not be trusted');
	});
});
