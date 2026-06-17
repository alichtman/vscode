/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { randomBytes } from 'crypto';
import { promises as fs } from 'fs';
import { Schemas } from '../../../base/common/network.js';
import { dirname, isAbsolute, join } from '../../../base/common/path.js';
import { URI } from '../../../base/common/uri.js';
import { IExtension } from '../../extensions/common/extensions.js';
import { ILogService } from '../../log/common/log.js';
import { resolveUriHandlerCsrfManifest, signUri } from '../common/uriHandlerCsrf.js';

const SECRET_BYTES = 64;
const SECRET_FILE_NAME = 'uri-csrf.secret';
const ROTATION_MS = 24 * 60 * 60 * 1000;

export interface IUriHandlerCsrfSecretLocation {
	readonly secretFile?: URI;
	readonly secretFileSpec?: string;
}

/** Resolve an explicit or manifest-provided secret location, falling back safely when invalid. */
export function resolveUriHandlerCsrfSecretFile(globalStorage: URI, location: IUriHandlerCsrfSecretLocation, logService: ILogService): URI {
	const defaultSecretFile = URI.joinPath(globalStorage, SECRET_FILE_NAME);
	if (location.secretFile) {
		if (isAbsoluteFileUri(location.secretFile)) {
			return location.secretFile;
		}
		logService.warn(`[uri-csrf] secretFile '${location.secretFile.toString()}' must be an absolute file URI; using the default location.`);
		return defaultSecretFile;
	}
	if (!location.secretFileSpec) {
		return defaultSecretFile;
	}

	const raw = location.secretFileSpec;
	const placeholder = '${globalStorage}';
	if (raw.startsWith(placeholder)) {
		const rest = raw.slice(placeholder.length).replace(/^[\\/]+/, '');
		if (rest && !rest.includes('${') && !rest.split(/[\\/]/).includes('..')) {
			return URI.joinPath(globalStorage, rest);
		}
		logService.warn(`[uri-csrf] secretFile '${raw}' must name a file within \${globalStorage}; using the default location.`);
		return defaultSecretFile;
	}
	if (raw.includes('${')) {
		logService.warn(`[uri-csrf] secretFile '${raw}' contains an unsupported placeholder (only \${globalStorage} is recognized); using the default location.`);
		return defaultSecretFile;
	}
	if (!isAbsolute(raw)) {
		logService.warn(`[uri-csrf] secretFile '${raw}' must be an absolute path; using the default location.`);
		return defaultSecretFile;
	}
	return URI.file(raw);
}

function isAbsoluteFileUri(uri: URI): boolean {
	return uri.scheme === Schemas.file && !uri.query && !uri.fragment && isAbsolute(uri.fsPath);
}

/** Provision the configured secret for an installed extension and return a signed URI. */
export async function signInstalledExtensionUri(uriValue: string, uriScheme: string, extensions: readonly IExtension[], globalStorageHome: URI, logService: ILogService): Promise<string> {
	const input = URI.parse(uriValue, true);
	if (input.scheme !== uriScheme || !input.authority) {
		throw new Error(`The URI must use the '${uriScheme}' scheme and an extension identifier as its authority.`);
	}

	const extension = extensions.find(candidate => candidate.identifier.id.toLowerCase() === input.authority.toLowerCase());
	if (!extension) {
		throw new Error(`Extension '${input.authority}' is not installed.`);
	}
	const csrf = resolveUriHandlerCsrfManifest(extension.manifest.contributes?.uriHandler);
	if (!csrf) {
		throw new Error(`Extension '${input.authority}' does not declare contributes.uriHandler.csrfProtection.`);
	}
	if (csrf.malformed) {
		throw new Error(`Extension '${input.authority}' has an invalid contributes.uriHandler.csrfProtection declaration.`);
	}

	const globalStorage = URI.joinPath(globalStorageHome, extension.identifier.id.toLowerCase());
	const secretFile = resolveUriHandlerCsrfSecretFile(globalStorage, csrf, logService);
	const secret = await new CsrfSecretStore(logService).getSecret(secretFile);
	if (!secret) {
		throw new Error(`The URI-handler secret for '${input.authority}' could not be created or trusted.`);
	}
	return (await signUri(secret, input)).toString(true);
}

interface ISecretFile {
	readonly version: number;
	readonly secret: string;
	readonly previousSecret?: string;
	readonly createdAt: number;
}

/** Owner/group-only, rotating secret store shared by the extension host and CLI signer. */
export class CsrfSecretStore {

	constructor(private readonly logService: ILogService) { }

	async getSecret(secretFile: URI): Promise<Uint8Array | undefined> {
		const path = secretFile.fsPath;
		const stat = await fs.stat(path).catch(() => undefined);
		if (stat) {
			if (!this.isTrusted(stat, path)) {
				return undefined;
			}
			const existing = await this.read(path);
			if (existing) {
				return existing.secret;
			}
		}

		try {
			return await this.write(path);
		} catch (err) {
			this.logService.error(`[uri-csrf] failed to write secret file at ${path}`, err);
			return undefined;
		}
	}

	async getPreviousSecret(secretFile: URI): Promise<Uint8Array | undefined> {
		const path = secretFile.fsPath;
		const stat = await fs.stat(path).catch(() => undefined);
		if (!stat || !this.isTrusted(stat, path)) {
			return undefined;
		}
		return (await this.read(path))?.previousSecret;
	}

	async rotateIfStale(secretFile: URI): Promise<void> {
		const path = secretFile.fsPath;
		const stat = await fs.stat(path).catch(() => undefined);
		if (!stat || !this.isTrusted(stat, path)) {
			return;
		}
		const existing = await this.read(path);
		if (existing && Date.now() - existing.createdAt > ROTATION_MS) {
			await this.write(path, existing.secret);
		}
	}

	private isTrusted(stat: { mode: number }, path: string): boolean {
		if ((stat.mode & 0o007) !== 0) {
			this.logService.warn(`[uri-csrf] secret file ${path} is world-accessible (mode ${(stat.mode & 0o777).toString(8)}); refusing to trust it`);
			return false;
		}
		return true;
	}

	private async read(path: string): Promise<{ secret: Uint8Array; previousSecret?: Uint8Array; createdAt: number } | undefined> {
		try {
			const parsed = JSON.parse(await fs.readFile(path, 'utf8')) as ISecretFile;
			if (parsed?.version !== 1 || typeof parsed.secret !== 'string' || typeof parsed.createdAt !== 'number') {
				return undefined;
			}
			const secret = new Uint8Array(Buffer.from(parsed.secret, 'base64'));
			if (secret.length < SECRET_BYTES) {
				return undefined;
			}
			const previousSecret = typeof parsed.previousSecret === 'string'
				? new Uint8Array(Buffer.from(parsed.previousSecret, 'base64'))
				: undefined;
			return { secret, previousSecret, createdAt: parsed.createdAt };
		} catch {
			return undefined;
		}
	}

	private async write(path: string, previous?: Uint8Array): Promise<Uint8Array> {
		const contents: ISecretFile = {
			version: 1,
			secret: randomBytes(SECRET_BYTES).toString('base64'),
			previousSecret: previous ? Buffer.from(previous).toString('base64') : undefined,
			createdAt: Date.now(),
		};
		const tmp = join(dirname(path), `.uri-csrf.${randomBytes(8).toString('hex')}.tmp`);
		try {
			await this.writeTmpAndRename(tmp, path, JSON.stringify(contents));
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
				await fs.mkdir(dirname(path), { recursive: true, mode: 0o700 });
				await this.writeTmpAndRename(tmp, path, JSON.stringify(contents));
			} else {
				await fs.unlink(tmp).catch(() => undefined);
				throw err;
			}
		}
		return (await this.read(path))?.secret ?? new Uint8Array(Buffer.from(contents.secret, 'base64'));
	}

	private async writeTmpAndRename(tmp: string, path: string, json: string): Promise<void> {
		await fs.writeFile(tmp, json, { mode: 0o600, flag: 'wx' });
		await fs.rename(tmp, path);
	}
}
