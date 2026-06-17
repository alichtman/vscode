/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type * as vscode from 'vscode';
import { MainContext, ExtHostUrlsShape, MainThreadUrlsShape } from './extHost.protocol.js';
import { URI, UriComponents } from '../../../base/common/uri.js';
import { toDisposable } from '../../../base/common/lifecycle.js';
import { onUnexpectedError } from '../../../base/common/errors.js';
import { ExtensionIdentifierSet, IExtensionDescription } from '../../../platform/extensions/common/extensions.js';
import { createDecorator } from '../../../platform/instantiation/common/instantiation.js';
import { IExtHostRpcService } from './extHostRpcService.js';
import { IExtHostUriHandlerCsrf } from './extHostUriHandlerCsrf.js';

export class ExtHostUrls implements ExtHostUrlsShape {

	declare _serviceBrand: undefined;

	private static HandlePool = 0;
	private readonly _proxy: MainThreadUrlsShape;

	private handles = new ExtensionIdentifierSet();
	private handlers = new Map<number, { readonly handler: vscode.UriHandler; readonly extension: IExtensionDescription }>();

	constructor(
		@IExtHostRpcService extHostRpc: IExtHostRpcService,
		@IExtHostUriHandlerCsrf private readonly csrf: IExtHostUriHandlerCsrf,
	) {
		this._proxy = extHostRpc.getProxy(MainContext.MainThreadUrls);
	}

	registerUriHandler(extension: IExtensionDescription, handler: vscode.UriHandler, options?: vscode.UriHandlerOptions): vscode.Disposable {
		const extensionId = extension.identifier;
		if (this.handles.has(extensionId)) {
			throw new Error(`Protocol handler already registered for extension ${extensionId}`);
		}

		const handle = ExtHostUrls.HandlePool++;
		this.handles.add(extensionId);
		this.handlers.set(handle, { handler, extension });
		const csrfDisposable = this.csrf.initialize(extension, options);
		this._proxy.$registerUriHandler(handle, extensionId, extension.displayName || extension.name);

		return toDisposable(() => {
			this.handles.delete(extensionId);
			this.handlers.delete(handle);
			csrfDisposable.dispose();
			this._proxy.$unregisterUriHandler(handle);
		});
	}

	async $handleExternalUri(handle: number, uri: UriComponents): Promise<void> {
		const entry = this.handlers.get(handle);
		if (!entry) {
			return;
		}

		const decision = await this.csrf.handle(entry.extension, URI.revive(uri));
		if (decision.kind === 'reject') {
			this._proxy.$notifyCsrfDeeplinkRejection(entry.extension.identifier, entry.extension.displayName || entry.extension.name);
			return;
		}

		try {
			entry.handler.handleUri(decision.uri);
		} catch (err) {
			onUnexpectedError(err);
		}
	}

	async createAppUri(uri: URI): Promise<vscode.Uri> {
		return URI.revive(await this._proxy.$createAppUri(uri));
	}
}

export interface IExtHostUrlsService extends ExtHostUrls { }
export const IExtHostUrlsService = createDecorator<IExtHostUrlsService>('IExtHostUrlsService');
