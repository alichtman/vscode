/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { URI } from '../../../../base/common/uri.js';
import { ensureNoDisposablesAreLeakedInTestSuite } from '../../../../base/test/common/utils.js';
import { ExtensionIdentifier, IExtensionDescription } from '../../../../platform/extensions/common/extensions.js';
import { NullExtHostUriHandlerCsrf, resolveUriHandlerCsrf } from '../../common/extHostUriHandlerCsrf.js';

/**
 * The web-worker (no local filesystem) CSRF behaviour and the shared config resolver. CSRF can't be
 * enforced without a local secret, so a protected handler either fails closed or, if it opted out,
 * dispatches unprotected.
 */
suite('NullExtHostUriHandlerCsrf / resolveUriHandlerCsrf', () => {

	ensureNoDisposablesAreLeakedInTestSuite();

	function extension(csrfProtection: unknown): IExtensionDescription {
		return {
			identifier: new ExtensionIdentifier('test.ext'),
			name: 'ext',
			displayName: 'Test Ext',
			contributes: { uriHandler: { csrfProtection } },
		} as unknown as IExtensionDescription;
	}

	test('resolver: manifest is authoritative and requires an unsupported-platform policy', () => {
		assert.strictEqual(resolveUriHandlerCsrf(extension(undefined)), undefined);
		assert.strictEqual(resolveUriHandlerCsrf(extension({ unsupportedPlatforms: 'allow' }))!.unsupportedPlatforms, 'allow');
		assert.strictEqual(resolveUriHandlerCsrf(extension({ unsupportedPlatforms: 'reject' }))!.unsupportedPlatforms, 'reject');
		assert.deepStrictEqual([...resolveUriHandlerCsrf(extension({ unsupportedPlatforms: 'reject', unprotectedPaths: ['/cb'] }))!.unprotectedPaths], ['/cb']);
		assert.strictEqual(resolveUriHandlerCsrf(extension(true))!.unsupportedPlatforms, 'reject', 'the removed boolean form must fail closed');
	});

	test('resolver: malformed untrusted manifest values fail closed', () => {
		const resolved = resolveUriHandlerCsrf(extension({ secretFile: 5, unprotectedPaths: ['/ok', 7] }))!;
		assert.strictEqual(resolved.secretFileSpec, undefined);
		assert.deepStrictEqual([...resolved.unprotectedPaths], []);
		assert.strictEqual(resolved.unsupportedPlatforms, 'reject', 'malformed security policy must reject');
	});

	test('resolver: unknown manifest properties fail closed', () => {
		const resolved = resolveUriHandlerCsrf(extension({ unsupportedPlatform: 'allow' }))!;
		assert.strictEqual(resolved.unsupportedPlatforms, 'reject', 'a typo must not silently allow unverified dispatch');
	});

	test('resolver: unknown uriHandler contribution properties fail closed', () => {
		const value = {
			identifier: new ExtensionIdentifier('test.ext'),
			name: 'ext',
			contributes: { uriHandler: { csrfProtecton: true } },
		} as unknown as IExtensionDescription;
		assert.strictEqual(resolveUriHandlerCsrf(value)!.unsupportedPlatforms, 'reject', 'a misspelled policy name must not disable protection');
	});

	test('allow policy dispatches a non-exempt link where CSRF cannot be enforced', async () => {
		const csrf = new NullExtHostUriHandlerCsrf();
		const contribution = { unsupportedPlatforms: 'allow' };
		const disposable = csrf.initialize(extension(contribution));
		const decision = await csrf.handle(extension(contribution), URI.parse('vscode://test.ext/start?x=1&vscode-csrf-token=token&vscode-csrf-ts=123'));
		assert.strictEqual(decision.kind, 'dispatch');
		if (decision.kind === 'dispatch') {
			assert.strictEqual(decision.uri.query, 'x=1');
		}
		disposable.dispose();
	});

	test('reject policy rejects a non-exempt link where CSRF cannot be enforced', async () => {
		const csrf = new NullExtHostUriHandlerCsrf();
		const contribution = { unsupportedPlatforms: 'reject' };
		const disposable = csrf.initialize(extension(contribution));
		const decision = await csrf.handle(extension(contribution), URI.parse('vscode://test.ext/start?x=1'));
		assert.strictEqual(decision.kind, 'reject');
		disposable.dispose();
	});

	test('reject policy still dispatches an exempt path', async () => {
		const csrf = new NullExtHostUriHandlerCsrf();
		const contribution = { unprotectedPaths: ['/did-authenticate'], unsupportedPlatforms: 'reject' };
		const disposable = csrf.initialize(extension(contribution));
		const decision = await csrf.handle(extension(contribution), URI.parse('vscode://test.ext/did-authenticate?code=abc&vscode-csrf-token=token&vscode-csrf-ts=123'));
		assert.strictEqual(decision.kind, 'dispatch');
		if (decision.kind === 'dispatch') {
			assert.strictEqual(decision.uri.query, 'code=abc');
		}
		disposable.dispose();
	});

	test('unprotected handler still has globally reserved parameters stripped', async () => {
		const csrf = new NullExtHostUriHandlerCsrf();
		csrf.initialize(extension(undefined));
		const decision = await csrf.handle(extension(undefined), URI.parse('vscode://test.ext/start?x=1&vscode-csrf-token=extension-value'));
		assert.strictEqual(decision.kind, 'dispatch');
		if (decision.kind === 'dispatch') {
			assert.strictEqual(decision.uri.query, 'x=1', 'reserved parameters are stripped globally');
		}
	});

	test('disposing a registration stops it from being tracked', async () => {
		const csrf = new NullExtHostUriHandlerCsrf();
		const contribution = { unsupportedPlatforms: 'reject' };
		csrf.initialize(extension(contribution)).dispose();
		const decision = await csrf.handle(extension(contribution), URI.parse('vscode://test.ext/start?x=1'));
		assert.strictEqual(decision.kind, 'dispatch', 'a disposed registration must no longer reject');
	});
});
