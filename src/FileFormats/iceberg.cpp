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

#include "iceberg.h"

// Fuzz Iceberg reader in 3 sequences:
// Sequence 1: Blind mutation of JSON metadata seed with Radamsa
// Sequence 2: Mutate every field value in same metadata seed
// Sequence 3: Mutate Avro based manifest list, but use original metadata seed

namespace fuzzberg {

IcebergFuzzer::IcebergFuzzer(pid_t target_pid,
                             std::string &mutation_file_path) {
  // Mirror parquet.cpp's ctor: persist the target pid so the
  // kill(this->_target_pid, SIGKILL) calls in the fuzz_* paths below
  // signal the forked target, not (with _target_pid == 0) the entire
  // process group.
  this->_target_pid = target_pid;
  std::cout << "Starting Iceberg fuzzer: " << mutation_file_path << std::endl;
  mutated_metadata_path = mutation_file_path + "/v3.metadata.json";
  mutated_manifest_list_name = mutation_file_path + "/manifest_list.avro";

  new_metadata_file_ptr = std::fopen(mutated_metadata_path.c_str(), "wb");
  new_manifest_file_ptr = std::fopen(mutated_manifest_list_name.c_str(), "wb");

  if (!new_manifest_file_ptr || !new_metadata_file_ptr) {
    std::cerr << "Could not create or open files for writing metadata and "
                 "manifest mutations: "
              << std::endl;
    perror("fopen");
    kill(target_pid, SIGKILL);
    exit(1);
  }
  radamsa_init();
}

namespace {

// Quote a SQL identifier per ANSI: wrap in double-quotes, double any
// internal double-quote. Belt-and-suspenders against weird column
// names that may appear in mutated schemas.
std::string quoteIdent(const std::string &name) {
  std::string out;
  out.reserve(name.size() + 2);
  out.push_back('"');
  for (char c : name) {
    if (c == '"') out.push_back('"');
    out.push_back(c);
  }
  out.push_back('"');
  return out;
}

// One type-appropriate predicate per Iceberg primitive type. Designed
// to land on the planner's predicate-pushdown / row-group min-max
// pruning paths:
//   * range filters on numeric/temporal → min/max walk
//   * equality/LIKE on string           → dict + truncated-stats
//   * presence on boolean / fallback    → null-bitmap walk
// Values are small constants chosen to be in-domain without depending
// on real seed-data distribution.
std::string predicateFor(const std::string &quoted_col,
                         const std::string &type) {
  if (type == "int" || type == "long")     return quoted_col + " > 0";
  if (type == "float" || type == "double") return quoted_col + " > 0.0";
  if (type == "string")                    return quoted_col + " = 'a'";
  if (type == "boolean")                   return quoted_col;
  if (type == "date")                      return quoted_col + " > DATE '2000-01-01'";
  if (type.rfind("timestamp", 0) == 0)     return quoted_col + " > TIMESTAMP '2000-01-01 00:00:00'";
  if (type.rfind("decimal", 0) == 0)       return quoted_col + " > 0";
  return quoted_col + " IS NOT NULL";
}

// Locate the active schema in an Iceberg metadata JSON. v1 puts it
// inline at `schema`; v2/v3 use `schemas` keyed by `current-schema-id`.
// Returns nullptr if no usable schema can be found (malformed mutation,
// missing keys, etc.) — caller treats that as "no filters this round".
const nlohmann::json *findCurrentSchema(const nlohmann::json &meta) {
  if (meta.contains("schemas") && meta["schemas"].is_array() &&
      !meta["schemas"].empty()) {
    int cur_id = -1;
    if (meta.contains("current-schema-id") &&
        meta["current-schema-id"].is_number_integer()) {
      cur_id = meta["current-schema-id"].get<int>();
    }
    for (const auto &s : meta["schemas"]) {
      if (s.is_object() && s.contains("schema-id") &&
          s["schema-id"].is_number_integer() &&
          s["schema-id"].get<int>() == cur_id) {
        return &s;
      }
    }
    // Fall back to the first schema if no exact match — happens for v1
    // metadata pulled into a v2-shaped corpus, plus mutations that
    // scramble current-schema-id away from any real entry.
    if (meta["schemas"][0].is_object()) {
      return &meta["schemas"][0];
    }
  }
  if (meta.contains("schema") && meta["schema"].is_object()) {
    return &meta["schema"];
  }
  return nullptr;
}

} // namespace

std::vector<std::string> IcebergFuzzer::buildColumnFilterQueries() const {
  std::vector<std::string> out;
  if (!add_column_filters || table_expr_for_column_filters.empty()) {
    return out;
  }
  const nlohmann::json *schema = findCurrentSchema(metadata_json);
  if (!schema || !schema->contains("fields") ||
      !(*schema)["fields"].is_array()) {
    return out;
  }
  for (const auto &f : (*schema)["fields"]) {
    if (!f.is_object()) continue;
    // Primitive Iceberg types come through as strings ("int", "long",
    // "string", "decimal(P,S)", "timestamp", ...). Complex types
    // (struct/list/map) come through as objects — skip those, they
    // can't be filter-predicated directly.
    if (!f.contains("name") || !f["name"].is_string()) continue;
    if (!f.contains("type") || !f["type"].is_string()) continue;
    const std::string col = f["name"].get<std::string>();
    const std::string type = f["type"].get<std::string>();
    out.push_back("SELECT * FROM " + table_expr_for_column_filters +
                  " WHERE " + predicateFor(quoteIdent(col), type) + ";");
  }
  return out;
}

CURLcode IcebergFuzzer::sendQueryAndAccount(CURL *curl,
                                             const std::string &query,
                                             const std::string &db_url,
                                             size_t &execs,
                                             size_t crash_size_on_failure) {
  execs++;
  std::cout << "\nQuery : " << query << std::endl;
  auto rc = send_query(curl, query, db_url, "");
  if (rc != CURLE_OK) {
    if (rc == CURLE_OPERATION_TIMEDOUT) {
      std::cerr << "Target timed out, kill child and stop fuzzing" << std::endl;
      kill(this->_target_pid, SIGKILL);
      exit(1);
    }
    crash_input_size = crash_size_on_failure;
  }
  return rc;
}

// Sequence 1
int8_t IcebergFuzzer::fuzz_metadata_random(std::vector<std::string> &queries,
                                           std::string &db_url,
                                           char *&radamsa_buffer, size_t &execs,
                                           CURL *curl,
                                           corpus_buffer &metadata_corpus) {
  // Guard against empty corpus. _load_corpus silently drops JSONs
  // missing `current-snapshot-id`; if every input was dropped we'd
  // otherwise `rand() % 0` → UB (SIGFPE on x86) and abort the fuzzer
  // mid-run with no useful diagnostic.
  if (metadata_corpus.empty()) {
    std::cerr << "iceberg fuzzer: metadata corpus is empty; aborting round\n";
    return -1;
  }

  auto seed = seed_generator();
  srand(seed);

  // pick a random metadata from the Metadata corpus
  size_t rand_metadata = rand() % metadata_corpus.size();

  this->metadata_json = nlohmann::json::parse(
      metadata_corpus[rand_metadata].corpus, nullptr, false);

  auto output_size = radamsa(reinterpret_cast<uint8_t *>(const_cast<char *>(
                                 metadata_corpus[rand_metadata].corpus)),
                             metadata_corpus[rand_metadata].size,
                             reinterpret_cast<uint8_t *>(radamsa_buffer),
                             RADAMSA_BUFFER_SIZE, seed);

  write_radamsa_mutation(radamsa_buffer, new_metadata_file_ptr, output_size);

  std::cout << "\n\n\033[1;36m********* Starting generic metadata fuzzing "
               "*********\033[0m\n\n"
            << std::endl;

  // User-supplied queries first, then per-iteration column-filter
  // queries derived from the mutated schema. The latter list is empty
  // when add_column_filters is off, or when the mutation produced an
  // unparseable / schema-less metadata (sequence 1 mutates raw bytes).
  for (auto const &query : queries) {
    if (sendQueryAndAccount(curl, query, db_url, execs, output_size) !=
        CURLE_OK) {
      std::fclose(new_metadata_file_ptr);
      std::fclose(new_manifest_file_ptr);
      return -1;
    }
  }
  for (auto const &query : buildColumnFilterQueries()) {
    if (sendQueryAndAccount(curl, query, db_url, execs, output_size) !=
        CURLE_OK) {
      std::fclose(new_metadata_file_ptr);
      std::fclose(new_manifest_file_ptr);
      return -1;
    }
  }
  // clear the buffer for next iteration
  memset(radamsa_buffer, 0, output_size);
  output_size = 0;
  return 0;
}

// Sequence 2

int8_t IcebergFuzzer::fuzz_metadata_structured(
    std::vector<std::string> &queries, std::string &db_url,
    char *&radamsa_buffer, size_t &execs, CURL *curl) {
  std::cout << "\n\n\033[1;35m********* Starting structured metadata fuzzing "
               "*********\033[0m\n\n"
            << std::endl;

  srand(seed_generator());
  std::string field_str = "";
  int nested_array_index = 0;
  std::string nested_key = "";
  bool is_nested_object = false;
  bool is_nested_array = false;
  std::string _key = "";

  for (const auto &[key, value] : this->metadata_json.items()) {
    // to restore original value post-mutation
    auto tmp = this->metadata_json[key];

    auto rand_ = rand() % 10;

    // Mutate nested fields with a probability of < 50%
    if (rand_ < 5) {
      if (value.is_object() && value.size() > 0) {
        std::cout
            << "\033[1;33mField is an object, descending further..\033[0m\n"
            << std::endl;
        nlohmann::json::iterator iter = value.begin();
        int object_index = rand() % value.size();
        std::advance(iter, object_index);
        nested_key = iter.key();
        _key = nested_key;
        field_str = value[nested_key].dump();
      } else if (value.is_array() && value.size() > 0) {
        std::cout
            << "\033[1;33mField is an array, traversing further..\033[0m\n"
            << std::endl;
        nested_array_index = rand() % value.size();
        if (value[nested_array_index].is_object() &&
            value[nested_array_index].size() > 0) {
          is_nested_object = true;
          int object_index = rand() % value[nested_array_index].size();
          nlohmann::json::iterator iter = value[nested_array_index].begin();
          std::advance(iter, object_index);
          nested_key = iter.key();
          _key = nested_key;
          field_str = value[nested_array_index][nested_key].dump();
        } else {
          field_str = value[nested_array_index].dump();
          is_nested_array = true;
          _key = key;
        }
      } else {
        field_str = metadata_json[key].dump();
        _key = key;
      }
    } else {
      field_str = metadata_json[key].dump();
      _key = key;
    }

    // Cap the retry loop. The original TODO acknowledged this: if
    // Radamsa happens to consistently produce JSON that fails to
    // parse for a particular seed+field combination, the
    // `goto mutate` retry would spin forever and the fuzz round
    // would never make progress. 8 attempts is generous; bail to
    // the next field on the 9th and leave this one unmutated.
    int mutate_retries = 0;
    static constexpr int kMaxMutateRetries = 8;
  mutate:
    auto output_size = radamsa(
        reinterpret_cast<uint8_t *>(const_cast<char *>(field_str.c_str())),
        field_str.size(), reinterpret_cast<uint8_t *>(radamsa_buffer),
        RADAMSA_BUFFER_SIZE - 1, seed_generator());

    radamsa_buffer[output_size] = '\0';

    auto parsed_value = nlohmann::json::parse(radamsa_buffer, nullptr, false);

    if (parsed_value.is_discarded()) {

      memset(radamsa_buffer, 0, output_size);
      output_size = 0;
      // try mutating the same field again
      if (++mutate_retries < kMaxMutateRetries) {
        goto mutate;
      }
      // Give up on this field — leave the metadata unchanged and
      // move on to the next one.
      continue;
    }

    if (rand_ < 5) {
      if (value.is_object()) {
        metadata_json[key][nested_key] = parsed_value;

      } else if (value.is_array()) {
        if (is_nested_object) {
          metadata_json[key][nested_array_index][nested_key] = parsed_value;
          is_nested_object = false;
        }
        if (is_nested_array) {
          metadata_json[key][nested_array_index] = parsed_value;
          is_nested_array = false;
        }
      } else {
        metadata_json[key] = parsed_value;
      }
    }

    auto metadata_mutated_string =
        metadata_json.dump(-1,    // no prettifying
                           ' ',   // indent char (unused)
                           false, // ensure_ascii false
                           nlohmann::json::error_handler_t::replace);

    auto metadata_mutated_structured =
        const_cast<char *>(metadata_mutated_string.c_str());

    if (_key != key) {
      std::cout << "Field Value: " << tmp.dump() << " , ";
    }

    std::cout << "Key: " << "\"" << _key << "\", "
              << "Original Value: " << field_str << ", "
              << "Mutated Value: \033[1;31m" << radamsa_buffer << "\033[0m\n"
              << std::endl;

    write_radamsa_mutation(metadata_mutated_structured, new_metadata_file_ptr,
                           strlen(metadata_mutated_structured));

    // User-supplied queries first, then column-filter queries derived
    // from the active (mutated) schema. Sequence 2's mutation targets
    // one field at a time and keeps the rest of metadata_json intact,
    // so the filters reliably reference live columns.
    for (auto const &query : queries) {
      if (sendQueryAndAccount(curl, query, db_url, execs, output_size) !=
          CURLE_OK) {
        std::fclose(new_metadata_file_ptr);
        std::fclose(new_manifest_file_ptr);
        return -1;
      }
    }
    for (auto const &query : buildColumnFilterQueries()) {
      if (sendQueryAndAccount(curl, query, db_url, execs, output_size) !=
          CURLE_OK) {
        std::fclose(new_metadata_file_ptr);
        std::fclose(new_manifest_file_ptr);
        return -1;
      }
    }
    // restore original key value
    metadata_json[key] = tmp;
    // clear the buffer for next iteration
    memset(radamsa_buffer, 0, output_size);
    output_size = 0;
  }
  return 0;
}

// Sequence 3
int8_t IcebergFuzzer::fuzz_manifest_list_structured(
    std::vector<std::string> &queries, std::string &db_url,
    corpus_buffer &manifest_corpus, char *&radamsa_buffer, size_t &execs,
    CURL *curl) {
  std::cout << "\n\n\033[1;34m********* Starting manifest list fuzzing "
               "*********\033[0m\n\n"
            << std::endl;

  // Same empty-corpus guard as sequence 1. _load_corpus silently
  // drops non-OBJ1 avro; without this, rand() % 0 SIGFPEs the fuzzer
  // mid-run when no manifest avro qualified.
  if (manifest_corpus.empty()) {
    std::cerr << "iceberg fuzzer: manifest corpus is empty; skipping sequence 3\n";
    return 0;
  }

  // Write updated metadata file
  if (!new_metadata_file_ptr) {
    std::cerr << "Invalid file for writing metadata" << std::endl;
    exit(1);
  }
  std::string metadata_str = this->metadata_json.dump(
      -1, ' ', false, nlohmann::json::error_handler_t::replace);
  ftruncate(fileno(new_metadata_file_ptr), 0);
  rewind(new_metadata_file_ptr);
  std::fwrite(metadata_str.c_str(), 1, metadata_str.size(),
              new_metadata_file_ptr);
  std::fflush(new_metadata_file_ptr);

  auto seed = seed_generator();
  srand(seed);
  size_t rand_manifest = rand() % manifest_corpus.size();

  // Guard against an Avro entry shorter than the 4-byte "OBJ1"
  // header. Without this, `size - 4` wraps as size_t to ~2^64-1 and
  // gets passed straight into radamsa() as the input length — OOB
  // reads + harness instability. Real Avro headers are 4 bytes, so
  // any shorter entry is malformed; skip the round.
  if (manifest_corpus[rand_manifest].size < 4) {
    std::cerr << "iceberg fuzzer: manifest entry " << rand_manifest
              << " shorter than Avro header (4 bytes); skipping round\n";
    return 0;
  }

  // Retain "OBJ1" header
  std::memcpy(radamsa_buffer, manifest_corpus[rand_manifest].corpus, 4);

  // Mutate Avro file (excluding header)
  auto manifest_size = manifest_corpus[rand_manifest].size - 4;
  auto output_size = radamsa(
      reinterpret_cast<uint8_t *>(manifest_corpus[rand_manifest].corpus + 4),
      manifest_size, reinterpret_cast<uint8_t *>(radamsa_buffer + 4),
      RADAMSA_BUFFER_SIZE - 4, seed);

  // --- Enhanced Avro fuzzing logic ---

  const char *fake_schema = "{\"type\":\"record\",\"name\":\"Fuzz\","
                            "\"fields\":[{\"name\":\"x\",\"type\":\"int\"}]}";

  // 1. Corrupt sync marker (last 16 bytes and after header)
  if (rand() % 10 < 3 && output_size + 4 > 20) {
    size_t sync_offset = output_size + 4 - 16;
    for (size_t i = 0; i < 16; ++i)
      if (rand() % 10 < 3)
        radamsa_buffer[sync_offset + i] = static_cast<char>(rand() % 256);
    size_t sync_marker_pos = 5;
    for (size_t i = 0; i < 16 && (sync_marker_pos + i) < output_size + 4; ++i)
      if (rand() % 10 < 3)
        radamsa_buffer[sync_marker_pos + i] = static_cast<char>(rand() % 256);
  }

  // 2. Mutate block count/length fields
  if (rand() % 10 < 3 && output_size > 24) {
    size_t block_meta_pos = 4 + 8 + rand() % 8;
    radamsa_buffer[block_meta_pos] = static_cast<char>(rand() % 256);
  }

  // 3. Insert random Avro schema fragments

  if (rand() % 10 < 3) {

    size_t insert_pos = 100 + rand() % 100;
    size_t schema_len = strlen(fake_schema);
    // We will possibly miss fake schema insertions if Radamsa mutations <
    // 199 + strlen(fake_schema) bytes, but that's fine
    if (insert_pos + schema_len < output_size) {
      memcpy(radamsa_buffer + insert_pos, fake_schema, schema_len);
    }
  }

  // 4. Truncate or pad file
  if (rand() % 2 == 0 && output_size > 32) {
    output_size -= rand() % 16;
  } else if (output_size + 16 < RADAMSA_BUFFER_SIZE - 4) {
    memset(radamsa_buffer + output_size + 4, 0x00, 16);
    output_size += 16;
  }

  // 5. Flip random bits in Avro blocks (simulate bit-level corruption)
  if (rand() % 10 < 3 && output_size > 64) {
    for (int i = 0; i < 8; ++i) {
      size_t pos = 4 + rand() % (output_size - 4);
      radamsa_buffer[pos] ^= (1 << (rand() % 8));
    }
  }

  // 6. Randomly duplicate or reorder blocks (simulate block-level confusion)
  if (output_size > 128 && (rand() % 10) < 2) {
    size_t block_start = 4 + rand() % (output_size / 2);
    size_t block_len = 16 + rand() % 32;
    // block_start + block_len < output_size: guards against overflows if
    // output_size is too small
    // output_size + block_len < RADAMSA_BUFFER_SIZE - 4: ensures we don't
    // exceed buffer limits
    if ((block_start + block_len < output_size) &&
        (output_size + block_len < RADAMSA_BUFFER_SIZE - 4)) {
      memmove(radamsa_buffer + block_start + block_len,
              radamsa_buffer + block_start, block_len);
      if (block_start + block_len + block_len > output_size)
        output_size += block_start + block_len + block_len - output_size;
    }
  }

  write_radamsa_mutation(radamsa_buffer, new_manifest_file_ptr,
                         output_size + 4);

  // User-supplied queries first, then column-filter queries derived
  // from the metadata's current schema. Sequence 3 rewrites metadata
  // from metadata_json (kept intact across iterations) and mutates
  // only the manifest-list Avro, so the filters always match.
  for (auto const &query : queries) {
    if (sendQueryAndAccount(curl, query, db_url, execs, output_size) !=
        CURLE_OK) {
      std::fclose(new_metadata_file_ptr);
      std::fclose(new_manifest_file_ptr);
      return -1;
    }
  }
  for (auto const &query : buildColumnFilterQueries()) {
    if (sendQueryAndAccount(curl, query, db_url, execs, output_size) !=
        CURLE_OK) {
      std::fclose(new_metadata_file_ptr);
      std::fclose(new_manifest_file_ptr);
      return -1;
    }
  }
  memset(radamsa_buffer, 0, output_size);
  output_size = 0;
  metadata_json.clear();

  // TODO:
  // - Move Avro fuzzing to a separate class (so we can fuzz read_avro() TVFs)
  // - Extend Avro fuzzing with more structure
  // - Extend Iceberg fuzzing to Manifest File layer by overwriting
  // manifest_path field in Manifest List

  return 0;
}
} // namespace fuzzberg