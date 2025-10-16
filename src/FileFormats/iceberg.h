/*

  Fuzzberg - a lightweight SQL fuzzer for Iceberg and other file formats
  ----------------------------------------------------------------------

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
#include <time.h>
#include <unistd.h>

#include <string>

#include "FileFuzzerBase.h"

namespace fuzzberg {

class IcebergFuzzer : public FileFuzzerBase {
 public:
  IcebergFuzzer(pid_t target_pid, std::string& fuzzer_mutation_path);
  ~IcebergFuzzer() = default;

  int8_t fuzz_metadata_random(std::vector<std::string>& queries, std::string& db_url,
                              char*& radamsa_buffer, size_t& execs, CURL* curl,
                              corpus_buffer& metadata_corpus);

  int8_t fuzz_metadata_structured(std::vector<std::string>& queries, std::string& db_url,
                                  char*& radamsa_buffer, size_t& execs, CURL* curl);

  int8_t fuzz_manifest_list_structured(std::vector<std::string>& queries, std::string& db_url,
                                       corpus_buffer& manifest_corpus, char*& radamsa_buffer,
                                       size_t& execs, CURL* curl);

  std::string mutated_metadata_path;
  std::string mutated_manifest_list_name;
  FILE* new_metadata_file_ptr = nullptr;
  FILE* new_manifest_file_ptr = nullptr;
  nlohmann::json metadata_json;
};
}  // namespace fuzzberg
