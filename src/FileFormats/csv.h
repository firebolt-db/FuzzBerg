/*

  Fuzzberg - a fuzzer for Iceberg and other file-format database readers
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

#include <iostream>
#include <vector>

#include "FileFuzzerBase.h"

namespace fuzzberg {

class CSVFuzzer : public FileFuzzerBase {
 public:
  CSVFuzzer(pid_t target_pid, std::string fuzzer_mutation_path);
  ~CSVFuzzer() = default;

  FILE* mutated_file_ptr = nullptr;
  int8_t Fuzz(std::vector<std::string>& queries, std::string& db_url, corpus_buffer& input_corpus,
              char*& radamsa_buffer, size_t& execs, CURL* curl) override;
};
}  // namespace fuzzberg
