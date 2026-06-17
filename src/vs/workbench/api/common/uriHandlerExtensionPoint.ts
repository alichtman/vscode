/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as nls from '../../../nls.js';
import { ExtensionsRegistry } from '../../services/extensions/common/extensionsRegistry.js';
import { IUriHandlerContribution } from '../../../platform/extensions/common/extensions.js';
import { isObject, isString } from '../../../base/common/types.js';

/**
 * The `contributes.uriHandler` extension point. Declaring CSRF protection here (rather than only at
 * runtime via `registerUriHandler`) makes it statically auditable.
 */
const uriHandlerExtPoint = ExtensionsRegistry.registerExtensionPoint<IUriHandlerContribution>({
	extensionPoint: 'uriHandler',
	jsonSchema: {
		description: nls.localize('contributes.uriHandler', "Configures the extension's `vscode.UriHandler` (system-wide `vscode://` deeplinks)."),
		type: 'object',
		additionalProperties: false,
		properties: {
			csrfProtection: {
				description: nls.localize('contributes.uriHandler.csrfProtection', "Require incoming URIs to carry a valid CSRF token (HMAC-signed by a local process) before they reach the handler."),
				type: 'object',
				additionalProperties: false,
				required: ['unsupportedPlatforms'],
				properties: {
					secretFile: {
						type: 'string',
						description: nls.localize('contributes.uriHandler.csrfProtection.secretFile', "Path to the shared secret file. Supports the `${globalStorage}` placeholder, or an absolute path. When omitted, a derivable default under the extension's global storage is used.")
					},
					unprotectedPaths: {
						type: 'array',
						description: nls.localize('contributes.uriHandler.csrfProtection.unprotectedPaths', "URI paths exempt from CSRF protection and dispatched without a token. Required for web-initiated paths a browser cannot sign, such as OAuth callbacks (for example, `/did-authenticate`)."),
						items: { type: 'string' }
					},
					unsupportedPlatforms: {
						type: 'string',
						enum: ['reject', 'allow'],
						description: nls.localize('contributes.uriHandler.csrfProtection.unsupportedPlatforms', "Required policy for environments where CSRF cannot be enforced, such as a web extension host or Windows: `reject` blocks every non-exempt URI; `allow` dispatches them without verification.")
					}
				}
			}
		}
	}
});

/**
 * Validates `contributes.uriHandler` declarations and surfaces problems in the extension's
 * diagnostics. The contribution is consumed in the extension host (see `ExtHostUrls`); this handler
 * exists to register the schema and report malformed config early.
 */
export class UriHandlerExtensionPoint {

	constructor() {
		uriHandlerExtPoint.setHandler((extensions) => {
			for (const extension of extensions) {
				const value = extension.value;
				const collector = extension.collector;

				if (!isObject(value)) {
					collector.error(nls.localize('invalid.uriHandler', "'contributes.uriHandler' must be an object."));
					continue;
				}

				const csrf = value.csrfProtection;
				if (csrf === undefined) {
					continue;
				}
				if (!isObject(csrf)) {
					collector.error(nls.localize('invalid.uriHandler.csrfProtection', "'contributes.uriHandler.csrfProtection' must be an object."));
					continue;
				}
				if (csrf.secretFile !== undefined && !isString(csrf.secretFile)) {
					collector.error(nls.localize('invalid.uriHandler.secretFile', "'contributes.uriHandler.csrfProtection.secretFile' must be a string."));
				} else if (isString(csrf.secretFile) && !isValidSecretFileSpec(csrf.secretFile)) {
					collector.error(nls.localize('invalid.uriHandler.secretFilePath', "'contributes.uriHandler.csrfProtection.secretFile' must be an absolute path or a file within '${globalStorage}'."));
				}
				if (csrf.unprotectedPaths !== undefined && (!Array.isArray(csrf.unprotectedPaths) || !csrf.unprotectedPaths.every(isString))) {
					collector.error(nls.localize('invalid.uriHandler.unprotectedPaths', "'contributes.uriHandler.csrfProtection.unprotectedPaths' must be an array of strings."));
				}
				if (csrf.unsupportedPlatforms !== 'allow' && csrf.unsupportedPlatforms !== 'reject') {
					collector.error(nls.localize('invalid.uriHandler.unsupportedPlatforms', "'contributes.uriHandler.csrfProtection.unsupportedPlatforms' must be 'allow' or 'reject'."));
				}
			}
		});
	}
}

function isValidSecretFileSpec(value: string): boolean {
	const placeholder = '${globalStorage}';
	if (value.startsWith(placeholder)) {
		const rest = value.slice(placeholder.length).replace(/^[\\/]+/, '');
		return !!rest && !rest.includes('${') && !rest.split(/[\\/]/).includes('..');
	}
	return value.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(value) || value.startsWith('\\\\');
}
