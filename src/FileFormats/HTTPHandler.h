/*

  Fuzzberg - a fuzzer for Iceberg and other file-format readers
  --------------------------------------------------------------

  Copyright 2025 [Firebolt Analytics, Inc.]. All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

#pragma once

#include <curl/curl.h>
#include <wait.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fuzzberg {
class HTTPHandler {
public:
  HTTPHandler() = default;
  ~HTTPHandler() = default;

  CURLcode curlinit(const std::string &db_url);
  CURLcode send_query(CURL *curl_handle, const std::string &query,
                      const std::string &db_url,
                      const std::string &auth_token = "");
};
} // namespace fuzzberg
