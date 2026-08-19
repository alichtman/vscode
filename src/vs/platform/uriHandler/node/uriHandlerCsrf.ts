/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { randomBytes } from 'crypto';
import { constants as fsConstants, promises as fs, Stats } from 'fs';
import { Schemas } from '../../../base/common/network.js';
import { dirname, isAbsolute, join } from '../../../base/common/path.js';
import { URI } from '../../../base/common/uri.js';
import { IExtension } from '../../extensions/common/extensions.js';
import { ILogService } from '../../log/common/log.js';
import { resolveUriHandlerCsrfManifest, signUri } from '../common/uriHandlerCsrf.js';

const SECRET_BYTES = 64;
const SECRET_FILE_NAME = 'uri-csrf.secret';
const ROTATION_MS = 24 * 60 * 60 * 1000;
const MAX_SECRET_FILE_BYTES = 16 * 1024;

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

interface IReadSecretFile {
	readonly secret: Uint8Array;
	readonly previousSecret?: Uint8Array;
	readonly createdAt: number;
	readonly stat: Stats;
}

type SecretReadResult =
	| { readonly kind: 'valid'; readonly value: IReadSecretFile }
	| { readonly kind: 'missing' }
	| { readonly kind: 'invalid' };

/** Owner/group-only, rotating secret store shared by the extension host and CLI signer. */
export class CsrfSecretStore {

	constructor(private readonly logService: ILogService) { }

	async getSecret(secretFile: URI): Promise<Uint8Array | undefined> {
		const path = secretFile.fsPath;
		if (!await this.ensureTrustedParent(path, true)) {
			return undefined;
		}

		const existing = await this.read(path);
		if (existing.kind === 'valid') {
			return existing.value.secret;
		}
		if (existing.kind === 'invalid') {
			return undefined;
		}

		try {
			return await this.create(path);
		} catch (err) {
			this.logService.error(`[uri-csrf] failed to write secret file at ${path}`, err);
			return undefined;
		}
	}

	async getPreviousSecret(secretFile: URI): Promise<Uint8Array | undefined> {
		const path = secretFile.fsPath;
		if (!await this.ensureTrustedParent(path, false)) {
			return undefined;
		}
		const existing = await this.read(path);
		return existing.kind === 'valid' ? existing.value.previousSecret : undefined;
	}

	async rotateIfStale(secretFile: URI): Promise<void> {
		const path = secretFile.fsPath;
		if (!await this.ensureTrustedParent(path, false)) {
			return;
		}

		const lockPath = `${path}.lock`;
		let lock;
		try {
			lock = await fs.open(lockPath, 'wx', 0o600);
		} catch (err) {
			const code = (err as NodeJS.ErrnoException).code;
			if (code === 'EEXIST') {
				return; // another window or process is already rotating this secret
			}
			if (code === 'ENOENT') {
				return; // the extension storage was removed after the parent check
			}
			throw err;
		}

		try {
			try {
				const existing = await this.read(path); // re-read after taking the inter-process lock
				if (existing.kind === 'valid' && Date.now() - existing.value.createdAt > ROTATION_MS) {
					await this.replace(path, existing.value);
				}
			} catch (err) {
				if ((err as NodeJS.ErrnoException).code !== 'ENOENT') {
					throw err;
				}
				// Rotation is best-effort. The extension can be removed while a queued rotation is
				// writing; a later getSecret call will provision it again if it is still needed.
			}
		} finally {
			try {
				await lock.close();
			} finally {
				await fs.unlink(lockPath).catch(() => undefined);
			}
		}
	}

	private isTrusted(stat: Stats, path: string): boolean {
		if (!stat.isFile()) {
			this.logService.warn(`[uri-csrf] secret path ${path} is not a regular file; refusing to trust it`);
			return false;
		}
		if (stat.size > MAX_SECRET_FILE_BYTES) {
			this.logService.warn(`[uri-csrf] secret file ${path} is unexpectedly large; refusing to trust it`);
			return false;
		}
		if (process.platform === 'win32') {
			return true;
		}
		if ((stat.mode & 0o007) !== 0) {
			this.logService.warn(`[uri-csrf] secret file ${path} is world-accessible (mode ${(stat.mode & 0o777).toString(8)}); refusing to trust it`);
			return false;
		}

		const effectiveUser = process.geteuid?.();
		if (effectiveUser !== undefined && effectiveUser !== 0 && stat.uid !== effectiveUser) {
			const groups = new Set(process.getgroups?.() ?? []);
			const effectiveGroup = process.getegid?.();
			if (effectiveGroup !== undefined) {
				groups.add(effectiveGroup);
			}
			if (!groups.has(stat.gid) || (stat.mode & 0o040) === 0) {
				this.logService.warn(`[uri-csrf] secret file ${path} is not owned by the current user or a readable group; refusing to trust it`);
				return false;
			}
		}
		return true;
	}

	private async read(path: string): Promise<SecretReadResult> {
		let handle;
		try {
			const flags = process.platform === 'win32' ? fsConstants.O_RDONLY : fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW;
			handle = await fs.open(path, flags);
			const stat = await handle.stat();
			if (!this.isTrusted(stat, path)) {
				return { kind: 'invalid' };
			}

			const parsed = JSON.parse(await handle.readFile('utf8')) as ISecretFile;
			if (parsed?.version !== 1 || typeof parsed.secret !== 'string' || !Number.isFinite(parsed.createdAt)) {
				return { kind: 'invalid' };
			}

			const secret = this.decodeSecret(parsed.secret);
			const previousSecret = parsed.previousSecret === undefined ? undefined : this.decodeSecret(parsed.previousSecret);
			if (!secret || (parsed.previousSecret !== undefined && !previousSecret)) {
				return { kind: 'invalid' };
			}
			return { kind: 'valid', value: { secret, previousSecret, createdAt: parsed.createdAt, stat } };
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
				return { kind: 'missing' };
			}
			this.logService.warn(`[uri-csrf] failed to securely read secret file at ${path}; refusing to trust it`, err);
			return { kind: 'invalid' };
		} finally {
			await handle?.close().catch(() => undefined);
		}
	}

	private decodeSecret(value: unknown): Uint8Array | undefined {
		if (typeof value !== 'string') {
			return undefined;
		}
		const decoded = new Uint8Array(Buffer.from(value, 'base64'));
		return decoded.length === SECRET_BYTES ? decoded : undefined;
	}

	private newContents(previous?: Uint8Array): ISecretFile {
		return {
			version: 1,
			secret: randomBytes(SECRET_BYTES).toString('base64'),
			previousSecret: previous ? Buffer.from(previous).toString('base64') : undefined,
			createdAt: Date.now(),
		};
	}

	private async create(path: string): Promise<Uint8Array | undefined> {
		const tmp = await this.writeTemporary(path, this.newContents(), 0o600);
		try {
			try {
				// A hard link installs the fully-written file without replacing a concurrent winner.
				await fs.link(tmp, path);
			} catch (err) {
				if ((err as NodeJS.ErrnoException).code !== 'EEXIST') {
					throw err;
				}
			}
		} finally {
			await fs.unlink(tmp).catch(() => undefined);
		}

		const installed = await this.read(path);
		return installed.kind === 'valid' ? installed.value.secret : undefined;
	}

	private async replace(path: string, previous: IReadSecretFile): Promise<void> {
		if (!this.canRotate(previous.stat, path)) {
			return;
		}

		const mode = previous.stat.mode & 0o770;
		const tmp = await this.writeTemporary(path, this.newContents(previous.secret), mode || 0o600, previous.stat);
		try {
			await fs.rename(tmp, path);
		} finally {
			await fs.unlink(tmp).catch(() => undefined);
		}
	}

	private canRotate(stat: Stats, path: string): boolean {
		if (process.platform === 'win32') {
			return true;
		}
		const effectiveUser = process.geteuid?.();
		if (effectiveUser === undefined || effectiveUser === 0 || stat.uid === effectiveUser) {
			return true;
		}
		this.logService.warn(`[uri-csrf] secret file ${path} is group-readable but not owned by the current user; skipping rotation`);
		return false;
	}

	private async writeTemporary(path: string, contents: ISecretFile, mode: number, sourceStat?: Stats): Promise<string> {
		const tmp = join(dirname(path), `.uri-csrf.${randomBytes(8).toString('hex')}.tmp`);
		let handle;
		try {
			handle = await fs.open(tmp, 'wx', mode);
			await handle.chmod(mode);
			if (sourceStat && process.platform !== 'win32') {
				await handle.chown(sourceStat.uid, sourceStat.gid);
			}
			await handle.writeFile(JSON.stringify(contents), 'utf8');
			await handle.sync();
			return tmp;
		} catch (err) {
			await fs.unlink(tmp).catch(() => undefined);
			throw err;
		} finally {
			await handle?.close().catch(() => undefined);
		}
	}

	private async ensureTrustedParent(path: string, create: boolean): Promise<boolean> {
		const parent = dirname(path);
		if (create) {
			try {
				await fs.mkdir(parent, { recursive: true, mode: 0o700 });
			} catch (err) {
				this.logService.warn(`[uri-csrf] failed to create secret directory ${parent}`, err);
				return false;
			}
		}

		try {
			const directParent = await fs.lstat(parent);
			if (directParent.isSymbolicLink() || !directParent.isDirectory()) {
				this.logService.warn(`[uri-csrf] secret directory ${parent} must be a real directory, not a symlink`);
				return false;
			}

			let current = await fs.realpath(parent);
			while (true) {
				const stat = await fs.lstat(current);
				if (!stat.isDirectory() || stat.isSymbolicLink()) {
					this.logService.warn(`[uri-csrf] secret directory chain contains a non-directory at ${current}`);
					return false;
				}
				if (process.platform !== 'win32' && !this.isTrustedDirectory(stat, current)) {
					return false;
				}

				const parentPath = dirname(current);
				if (parentPath === current) {
					break;
				}
				current = parentPath;
			}
			return true;
		} catch (err) {
			this.logService.warn(`[uri-csrf] failed to validate secret directory ${parent}`, err);
			return false;
		}
	}

	private isTrustedDirectory(stat: Stats, path: string): boolean {
		const worldWritable = (stat.mode & 0o002) !== 0;
		const sticky = (stat.mode & 0o1000) !== 0;
		if (worldWritable && !sticky) {
			this.logService.warn(`[uri-csrf] secret directory ${path} is world-writable without the sticky bit; refusing to use it`);
			return false;
		}

		if ((stat.mode & 0o020) !== 0) {
			const groups = new Set(process.getgroups?.() ?? []);
			const effectiveGroup = process.getegid?.();
			if (effectiveGroup !== undefined) {
				groups.add(effectiveGroup);
			}
			if (!groups.has(stat.gid)) {
				this.logService.warn(`[uri-csrf] secret directory ${path} is writable by an unrelated group; refusing to use it`);
				return false;
			}
		}
		return true;
	}
}
