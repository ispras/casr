#!/usr/bin/env lua
--
-- Copyright 2025 ISP RAS
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
--------------------------------------------------------------------------

local xml2lua = require("xml2lua")
local handler = require("xmlhandler.tree")
local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    if #buf < 2 then return nil end
    local str = fdp:consume_string(#buf - 1)
    local parser = xml2lua.parser(handler)
    parser:parse(str)
end

local buf = io.read("*all")
if not buf then return nil end
TestOneInput(buf)
