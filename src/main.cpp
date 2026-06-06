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

#include <Databases/duckdb/duckdb.h>
#include <Databases/firebolt-core/firebolt-core.h>
#include <dirent.h>
#include <getopt.h>
#include <time.h>
#include <unistd.h>

#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>

constexpr const char *Green = "\033[32m";
constexpr const char *Yellow = "\033[33m";
constexpr const char *Reset = "\033[0m";

// query execution counter
size_t _execs = 0;
sigjmp_buf env;

static pid_t target_pid;

static struct timeval t1, t2;

volatile sig_atomic_t interrupted =
    0; // flag to indicate if the process was interrupted

// Interrupt handler to dump code coverage (optional) and kill target
void interrupt(int signal) {
  if (signal != SIGINT) {
    return;
  }
  if (target_pid > 0) {
    std::cout << "\033[1;33m\n\n[INFO] Fuzzing session interrupted\033[0m\n"
              << std::endl;
    std::cout << "\033[1;33m\n[INFO] Sending SIGUSR1 to target (PID: "
              << target_pid
              << ") to flush code coverage (if target handles it).\033[0m\n";
    kill(target_pid, SIGUSR1); // Request target to flush code coverage
    sleep(10);                 // Wait for the target to process the signal

    std::cout << "\033[1;31m\n[INFO] Terminating target process (PID: "
              << target_pid << ")\033[0m\n";
    kill(target_pid, SIGKILL); // Kill the target process
  }
  interrupted = 1;
  siglongjmp(env, 1);
}

int main(int argc, char *argv[]) {
  if (argc <= 1) {
    fprintf(stderr,
            "Please provide all the necessary arguments to fuzz target DB\n\n");
    exit(1);
  }

  int status;                     // child proc status
  std::signal(SIGINT, interrupt); // register handler for ctrl+c

  std::string target_bin_path;      // path to fuzz target
  std::string corpus_dir;           // path to input corpus
  std::string crash_dir;            // path to write crash output
  std::string fuzzer_mutation_path; // directory path to store fuzzer mutations
  std::string auth_token;           // optional auth token for target db server
  std::string format;               // file format to fuzz
  std::string db_url;               // URL for target db server
  std::string s3_bucket;            // S3 bucket name for Iceberg
  std::string database; // database name to fuzz (initializes the corresponding
                        // target class)
  std::string queries;  // path to JSON file containing queries to execute

  std::unique_ptr<fuzzberg::DatabaseHandler> fuzz_target;

  static struct option long_options[] = {
      {"database", required_argument, NULL, 'd'},
      {"bin", required_argument, NULL, 'b'},
      {"input", required_argument, NULL, 'i'},
      {"output", required_argument, NULL, 'o'},
      {"mutate", required_argument, NULL, 'm'},
      {"auth", required_argument, NULL, 't'},
      {"format", required_argument, NULL, 'f'},
      {"url", required_argument, NULL, 'u'},
      {"queries", required_argument, NULL, 'q'},
      {"bucket", required_argument, NULL, 'B'},
      {0, 0, 0, 0}};
  int option_index = 0;
  int result = 0;

  // Parse all options in a single pass and initialize fuzz_target when database
  // is found
  optind = 1;
  while ((result = getopt_long(argc, argv, "b:i:o:m:t:f:u:q:B:d:", long_options,
                               &option_index)) != -1) {
    switch (result) {
    case 'd':
      if (optarg) {
        database = optarg;
      }
      break;
    case 'b':
      if (optarg) {
        target_bin_path = optarg;
      } else {
        std::cerr << "\nPlease provide a valid target binary path\n";
        exit(1);
      }
      break;
    case 'i':
      if (optarg) {
        corpus_dir = optarg;
        if (!std::filesystem::exists(corpus_dir)) {
          std::cerr << "\nCorpus dir does not exist, exiting..\n";
          exit(1);
        }
      } else {
        std::cerr << "\nPlease provide a valid corpus directory path\n";
        exit(1);
      }
      break;
    case 'o':
      if (optarg) {
        crash_dir = optarg;
      } else {
        crash_dir = "/tmp/fuzzer_crashes"; // default crash directory
      }
      break;
    case 'm':
      if (optarg) {
        fuzzer_mutation_path = optarg;
        if (!std::filesystem::exists(fuzzer_mutation_path)) {
          std::cerr << "Folder does not exist, creating it.." << std::endl;
          std::filesystem::create_directories(fuzzer_mutation_path);
        }
      }
      break;
    case 't': // JWT token for authentication (optional)
      if (optarg) {
        auth_token = optarg;
      }
      break;
    case 'B':
      if (optarg) {
        s3_bucket = optarg;
      }
      break;
    case 'f':
      if (optarg) {
        format = optarg;
        if (format != "csv" && format != "parquet" && format != "iceberg") {
          std::cerr << "\nPlease provide a valid file format to fuzz\n";
          exit(1);
        }
      }
      break;
    case 'u':
      if (optarg) {
        db_url = optarg;
      } else {
        std::cerr << "\nPlease provide a valid URL to database server\n";
        exit(1);
      }
      break;
    case 'q':
      if (optarg) {
        queries = optarg;
      } else {
        std::cerr << "\nPlease provide a valid list of queries to execute\n";
        exit(1);
      }
      break;
    default: /* '?' */
    {
      fprintf(
          stderr,
          "\nUsage: %s [OPTIONS]\n\n"
          "Required:\n"
          "  -d, --database NAME         Database name (e.g., duckdb, "
          "firebolt)\n"
          "  -f, --format FORMAT         File format (csv, parquet, iceberg)\n"
          "  -u, --url URL               Database server URL\n"
          "  -i, --input DIR             Input corpus directory\n"
          "  -o, --output DIR            Output (crash) directory\n"
          "  -b, --bin PATH              Path to the target binary\n"
          "  -m, --mutate FILE           Mutation payload file\n"
          "  -q, --queries FILE          JSON file containing queries\n"
          "Optional:\n"
          "  -t, --auth TOKEN            Authentication token (JWT)\n"
          "  -B, --bucket BUCKET_NAME    S3 bucket name for Iceberg, or the "
          "literal\n"
          "                              \"file\" to write file:// URLs into "
          "metadata\n"
          "                              (required if --format=iceberg)\n",
          argv[0]);
      exit(1);
    }
    }
  }

  // At this point, optind indexes the first non-option argument:
  int idx = optind;

  // === Collect launcher args passed by user after '-b binary_path' ===
  std::vector<std::string> user_bin_args;
  for (int i = idx; i < argc; ++i) {
    user_bin_args.emplace_back(argv[i]);
  }

  // === Build arguments list for execv ===
  std::vector<std::string> arg_strings;
  arg_strings.push_back(target_bin_path);
  arg_strings.insert(arg_strings.end(), user_bin_args.begin(),
                     user_bin_args.end());

  // Convert to char* array for execv
  std::vector<char *> execv_args;
  execv_args.reserve(arg_strings.size() + 1);
  for (auto &s : arg_strings) {
    execv_args.push_back(const_cast<char *>(s.c_str()));
  }
  execv_args.push_back(nullptr);

  // Initialize fuzz_target based on database
  if (database == "firebolt") {
    fuzz_target = std::make_unique<fuzzberg::FireboltCore>();
  } else if (database == "duckdb") {
    fuzz_target = std::make_unique<fuzzberg::DuckDB>();
  } else {
    std::cout << "\nPlease provide a valid database name to fuzz\n";
    exit(1);
  }

  // Set file-format to fuzz
  if (format == "csv") {
    fuzz_target->file_format = "csv";
  } else if (format == "parquet") {
    fuzz_target->file_format = "parquet";
  } else if (format == "iceberg") {
    if (s3_bucket.empty()) {
      std::cerr << "Error: --bucket (-B) must be provided when using "
                   "--format=iceberg\n";
      exit(1);
    }
    fuzz_target->file_format = "iceberg";
    fuzz_target->s3_bucket = s3_bucket;
  } else {
    std::cerr << "Allowed options (lower case only): csv, parquet, iceberg\n\n";
    exit(1);
  }

  fuzz_target->execv_args = execv_args; // store execv args in fuzzer
  fuzz_target->db_url = db_url;         // store db_url in fuzzer
  fuzz_target->fuzzer_mutation_path =
      fuzzer_mutation_path;              // store mutation_file_path in fuzzer
  fuzz_target->_auth_token = auth_token; // store auth token in fuzzer

  // Load queries to execute
  std::ifstream query_file(queries);
  if (!query_file.is_open()) {
    std::cerr << "Could not open query file: " << optarg << std::endl;
    exit(1);
  }

  nlohmann::json queries_json;
  queries_json = nlohmann::json::parse(query_file, nullptr, false);
  if (queries_json.is_discarded() || !queries_json.contains("queries") ||
      !queries_json["queries"].is_array()) {
    std::cerr << "Error: Invalid JSON format in query file. Expected an array "
                 "of queries under "
                 "'queries' key.\n";

    query_file.close();
    exit(1);
  }
  query_file.close();

  for (const auto &query : queries_json["queries"]) {
    fuzz_target->queries.push_back(query.get<std::string>());
  }
  std::cout << "\n" << Green << "[INFO] Loaded " << fuzz_target->queries.size()
            << " queries from: " << Reset << queries << "\n" << std::endl;

  // Optional: per-iteration column-filter queries. When `add_column_filters`
  // is true in queries.json, the Iceberg fuzzer also runs one
  // `SELECT * FROM <table_expr> WHERE "<col>" <type-appropriate-predicate>`
  // per primitive column of the just-mutated schema, on top of the static
  // list above. Requires a sibling `table_expr` key (string) — the FROM
  // clause for the synthesized queries. Tolerates older queries.json files
  // that don't define either key.
  if (queries_json.contains("add_column_filters") &&
      queries_json["add_column_filters"].is_boolean() &&
      queries_json["add_column_filters"].get<bool>()) {
    if (!queries_json.contains("table_expr") ||
        !queries_json["table_expr"].is_string() ||
        queries_json["table_expr"].get<std::string>().empty()) {
      std::cerr << "Error: queries.json sets `add_column_filters: true` but "
                   "is missing a non-empty string `table_expr` key — that's "
                   "the FROM expression the synthesized WHERE queries are "
                   "anchored to.\n";
      exit(1);
    }
    fuzz_target->add_column_filters = true;
    fuzz_target->table_expr_for_column_filters =
        queries_json["table_expr"].get<std::string>();
    std::cout << Green << "[INFO] add_column_filters enabled; table_expr: "
              << Reset << fuzz_target->table_expr_for_column_filters << "\n"
              << std::endl;
  }

  // Load seed corpus
  std::cout << "Loading seed corpus from: " << corpus_dir << "\n"
            << std::endl;
  fuzz_target->_load_corpus(corpus_dir);

  // Track whether the cleanup path observed a crash so main() can
  // propagate it as a non-zero exit. Without this, main always
  // returned 0 even after detecting a real SIGSEGV/SIGABRT from the
  // target — orchestrators / CI gating on the exit code never tripped.
  bool target_crashed = false;

  if (sigsetjmp(env, 1) != 0) {
    // jumps to interrupt: from SIGHANDLER
    goto interrupt;
  }

  // Fork and exec the target database
  target_pid = fuzz_target->ForkTarget();

  // call fuzzer
  gettimeofday(&t1, NULL);
fuzz:
  if (fuzz_target->fuzz() == -1) {
    // When fuzz() returns -1, the target server may either be already
    // dead (real crash — curl couldn't connect because the engine
    // SEGV'd / aborted) or still healthy (harness error — empty
    // corpus, transport hiccup, file-system error). Distinguish via
    // WNOHANG:
    //
    //   * still alive (WNOHANG returns 0) → harness error; SIGKILL the
    //     target, reap with blocking waitpid, and route past the
    //     crash-detection logic via the `interrupt` label so we don't
    //     write a bogus crash artifact for the SIGKILL we sent.
    //   * already dead (WNOHANG returns child_pid) → real crash;
    //     feed its status into the crash-detection logic.
    //   * WNOHANG < 0 (ECHILD) → fall through to cleanup as-is.
    //
    // Without this distinguisher the previous behavior (unconditional
    // blocking waitpid) stalls for the outer timeout budget on harness
    // errors and masks them as long silent runs.
    int wn_status = 0;
    pid_t wn = waitpid(fuzz_target->target_pid, &wn_status, WNOHANG);
    if (wn == 0) {
      std::cerr << "fuzz() returned -1 but target still running — "
                   "treating as harness error, not crash\n";
      if (fuzz_target->target_pid > 0) {
        kill(fuzz_target->target_pid, SIGKILL);
        waitpid(fuzz_target->target_pid, &wn_status, 0);
      }
      goto interrupt;
    }
    if (wn > 0) {
      status = wn_status;
      goto cleanup_inspect;
    }
    goto cleanup;
  }

cleanup:
  if (waitpid(fuzz_target->target_pid, &status, 0) < 0) {
    std::perror("waitpid failed");
  }
cleanup_inspect:
  if (WIFSIGNALED(status)) {
    int signal = WTERMSIG(status);
    if (signal == SIGSEGV) {
      std::cout << "\nTarget crashed with SIGSEGV\n\n" << std::endl;
    } else if (signal == SIGABRT) {
      std::cout << "\nTarget crashed with SIGABRT\n\n" << std::endl;
    }
    std::cout << "Writing crash data to: " << crash_dir << "\n\n";
    fuzz_target->_write_crash(fuzz_target->radamsa_output, crash_dir);
    target_crashed = true;
  } else if (WIFEXITED(status)) {
    // WEXITSTATUS is only defined when WIFEXITED is true; reading it
    // after WIFSIGNALED / WIFSTOPPED is UB. With default waitpid
    // flags only WIFEXITED or WIFSIGNALED can be true, so this is
    // mostly a robustness improvement against future option changes.
    if (WEXITSTATUS(status) != 0) {
      std::cout << "Target process exited abnormally\n";
      fuzz_target->_write_crash(fuzz_target->radamsa_output, crash_dir);
      target_crashed = true;
    }
  }

interrupt:                     // section executed on receiving SIGINT
  _execs = fuzz_target->execs; // get number of queries executed by fuzzer

  fuzz_target->cleanup(); // cleanup fuzzer state
  gettimeofday(&t2, NULL);
  auto elapsedTime = (t2.tv_sec - t1.tv_sec);

  size_t seconds = elapsedTime % 60;
  size_t minutes = (elapsedTime / 60) % 60;
  size_t hours = (elapsedTime / 3600) % 24;
  size_t days = elapsedTime / (3600 * 24);

  std::cout << "\n"
            << Yellow << std::left << std::setw(15) << "Executions:" << Reset
            << std::right << Green << std::setw(8) << _execs << Reset << "\n"
            << Yellow << std::left << std::setw(15) << "Elapsed Time:" << Reset
            << std::right << Green << std::setw(2) << days << "d "
            << std::setw(2) << hours << "h " << std::setw(2) << minutes << "m "
            << std::setw(2) << seconds << "s" << Reset << "\n\n";

  return target_crashed ? 1 : 0;
}