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
#include <time.h>
#include <unistd.h>

#include <string>

#include "FileFuzzerBase.h"

namespace fuzzberg {

class IcebergFuzzer : public FileFuzzerBase {
public:
  IcebergFuzzer(pid_t target_pid, std::string &fuzzer_mutation_path);
  ~IcebergFuzzer() = default;

  int8_t fuzz_metadata_random(std::vector<std::string> &queries,
                              std::string &db_url, char *&radamsa_buffer,
                              size_t &execs, CURL *curl,
                              corpus_buffer &metadata_corpus);

  int8_t fuzz_metadata_structured(std::vector<std::string> &queries,
                                  std::string &db_url, char *&radamsa_buffer,
                                  size_t &execs, CURL *curl);

  int8_t fuzz_manifest_list_structured(std::vector<std::string> &queries,
                                       std::string &db_url,
                                       corpus_buffer &manifest_corpus,
                                       char *&radamsa_buffer, size_t &execs,
                                       CURL *curl);

  std::string mutated_metadata_path;
  std::string mutated_manifest_list_name;
  FILE *new_metadata_file_ptr = nullptr;
  FILE *new_manifest_file_ptr = nullptr;
  nlohmann::json metadata_json;

  // When non-empty, FuzzBerg synthesizes one additional `SELECT *` per
  // primitive column in the just-mutated schema and runs it alongside
  // the user-supplied queries. Each generated query is of the form:
  //
  //   SELECT * FROM <table_expr_for_column_filters> WHERE "<col>" <pred>
  //
  // where <pred> is a type-appropriate template designed to make the
  // engine walk row-group min/max stats (range filters on numeric /
  // temporal, equality/LIKE on strings, presence on boolean/binary).
  //
  // Without this, the engine's predicate-pushdown / stats-pruning
  // code path is never exercised by FuzzBerg — only the unfiltered
  // scan path is. Enabling it on a per-iteration basis means the
  // synthesized queries always reference columns that actually exist
  // in the active mutation's schema (no wasted "column not found"
  // plan errors).
  //
  // Set by `firebolt-core.cpp` from the `queries.json` `table_expr`
  // key when `add_column_filters: true` is present.
  std::string table_expr_for_column_filters;
  bool add_column_filters = false;

private:
  // Build the per-iteration WHERE-bearing queries from the current
  // metadata_json (sequence 1/2/3 all leave it as the just-written
  // schema). Returns an empty vector if `add_column_filters` is off,
  // the schema can't be located, or no primitive columns are present.
  std::vector<std::string> buildColumnFilterQueries() const;

  // Send a single query through curl; encapsulates the per-query
  // bookkeeping (execs++ , timeout-kills-target, crash-size capture)
  // that was previously duplicated across the three fuzz_* sequences.
  // Returns CURLE_OK on success, the underlying curl code otherwise.
  // `crash_size_on_failure` is recorded into crash_input_size if the
  // send fails for a non-timeout reason.
  CURLcode sendQueryAndAccount(CURL *curl, const std::string &query,
                               const std::string &db_url, size_t &execs,
                               size_t crash_size_on_failure);
};
} // namespace fuzzberg
