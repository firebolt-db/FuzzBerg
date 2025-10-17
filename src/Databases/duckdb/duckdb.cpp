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

#include "duckdb.h"

namespace fuzzberg {
pid_t DuckDB::ForkTarget() {
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    exit(1);
  } else if (pid == 0) {
    execv(execv_args[0], execv_args.data());
    perror("execv failed");
    exit(1);
  }

  // Parent
  FileFuzzerBase fuzzer_base;
  auto init_code = fuzzer_base.curlinit(db_url); // Test connection to target
  if (init_code != CURLE_OK) {
    std::cerr << "\nConnection to local server failed, fuzzer exiting..\n"
              << std::endl;
    exit(1);
  } else {
    std::cout << "Start fuzzing...\n";
    this->curl = curl_easy_init(); // re-use handle to speed up fuzzing
    this->target_pid = pid;        // set child PIDin fuzzer
  }

  return target_pid;
};

int8_t DuckDB::fuzz() {
  // CSV Fuzzer
  if (file_format == "csv") {
    CSVFuzzer csv_fuzzer(this->target_pid, this->fuzzer_mutation_path);
    auto status =
        csv_fuzzer.Fuzz(this->queries, this->db_url, this->input_corpus,
                        this->radamsa_output, this->execs, this->curl);

    if (status == -1) {
      return -1;
    }
  }

  return 0;
}
} // namespace fuzzberg