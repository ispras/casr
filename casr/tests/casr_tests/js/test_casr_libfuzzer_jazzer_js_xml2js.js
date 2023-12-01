/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// The code in this file is based on the examples available in JSFuzz:
// https://gitlab.com/gitlab-org/security-products/analyzers/fuzzers/jsfuzz/-/blob/34a694a8c73bfe0895c4e24784ba5b6dfe964b94/examples/xml/fuzz.js
// The original code is available under the Apache License 2.0.

const xml2js = require("xml2js");

/**
 * @param { Buffer } data
 */
module.exports.fuzz = async function (data) {
	try {
		await xml2js.parseStringPromise(data.toString(), {});
	} catch (error) {
		if (!ignoredError(error)) throw error;
	}
};

function ignoredError(error) {
	return !!ignored.find((message) => error.message.startsWith(message));
}

const ignored = [
	"Non-whitespace before first tag",
	"Unencoded",
	"Unexpected end",
	"Invalid character",
	"Invalid attribute name",
	"Invalid tagname",
	"Unclosed root tag",
	"Attribute without value",
	"Forward-slash in opening tag",
	"Text data outside of root node",
	"Unquoted attribute value",
	"Unmatched closing tag",
	"No whitespace between attributes",
	"Unexpected close tag",
];
