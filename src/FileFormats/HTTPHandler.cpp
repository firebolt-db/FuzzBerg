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

#include "HTTPHandler.h"

namespace fuzzberg {

CURLcode HTTPHandler::send_query(CURL *curl, const std::string &query,
                                 const std::string &db_url,
                                 const std::string &auth_token) {
  curl_off_t post_size = query.length();
  if (!auth_token.empty()) {
    struct curl_slist *list = NULL;
    std::string header_prefix = "F-Authorization: Bearer ";
    std::string auth_header = header_prefix + auth_token;
    list = curl_slist_append(list, auth_header.c_str());
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(curl, CURLOPT_URL, db_url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, post_size);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L); // 15 second timeout

  } else {
    curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, 102400L);
    curl_easy_setopt(curl, CURLOPT_URL, db_url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, post_size);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 50L);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L); // 15 second timeout
  }
  // we free the curl handle during Database object cleanup (e.g. when fuzzing
  // is interrupted, or crash is detected)
  return (curl_easy_perform(curl));
}

CURLcode HTTPHandler::curlinit(const std::string &db_url) {
  std::cout << "\nChecking connection to server...\n\n" << std::endl;
  sleep(8);
  CURL *curl_init = curl_easy_init();
  if (curl_init) {
    CURLcode ret;
    curl_easy_setopt(curl_init, CURLOPT_URL, db_url.c_str());
    curl_easy_setopt(curl_init, CURLOPT_CONNECT_ONLY, 1L);
    ret = curl_easy_perform(curl_init);
    if (ret == CURLE_OK) {
      std::cout << "\nConnected..." << std::endl;
      // create a database if target expects one for query executions (e.g.
      // in URL: http:://localhost:<port>/?database=fuzzberg)
      /* send_query(curl_init, "create database if not exists fuzzberg",
                  db_url, "");*/
      curl_easy_cleanup(curl_init);
    } else {
      std::cout << "\nDB server not starting, exiting..\n" << std::endl;
    }
    return ret;
  } else {
    std::cout << "\nCurl init failed, exiting..\n" << std::endl;
    exit(1);
  }
}

} // namespace fuzzberg
