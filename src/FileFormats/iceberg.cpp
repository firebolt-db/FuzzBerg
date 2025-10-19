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

// Sequence 1
int8_t IcebergFuzzer::fuzz_metadata_random(std::vector<std::string> &queries,
                                           std::string &db_url,
                                           char *&radamsa_buffer, size_t &execs,
                                           CURL *curl,
                                           corpus_buffer &metadata_corpus) {

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

  for (auto const &query : queries) {
    execs++;
    std::cout << "\nQuery : " << query << std::endl;
    auto return_code = send_query(curl, query, db_url, "");
    if (return_code != CURLE_OK) {
      std::cout << "CURL error: " << return_code << " - "
                << curl_easy_strerror(return_code) << std::endl;
      exit(1);

      // save size of the crash file
      crash_input_size = output_size;
      std::fclose(new_metadata_file_ptr);
      std::fclose(new_manifest_file_ptr);
      return -1;
    } else {
      continue;
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
      // TODO: add a retry counter
      goto mutate;
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

    // send query
    for (auto const &query : queries) {
      execs++;
      std::cout << "\nQuery : "
                << " " << query << "\n"
                << std::endl;
      auto return_code = send_query(curl, query, db_url, "");
      if (return_code != CURLE_OK) {
        // save size of the crash file
        crash_input_size = output_size;
        std::fclose(new_metadata_file_ptr);
        std::fclose(new_manifest_file_ptr);
        return -1;
      } else {
        continue;
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

  std::cout << "Avro data: " << radamsa_buffer << std::endl;
  write_radamsa_mutation(radamsa_buffer, new_manifest_file_ptr,
                         output_size + 4);

  // send query
  for (auto const &query : queries) {
    execs++;
    std::cout << "\nQuery : " << " " << query << "\n" << std::endl;
    auto return_code = send_query(curl, query, db_url, "");
    if (return_code != CURLE_OK) {
      // save size of the crash file
      crash_input_size = output_size;
      std::fclose(new_metadata_file_ptr);
      std::fclose(new_manifest_file_ptr);
      return -1;
    } else {
      continue;
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