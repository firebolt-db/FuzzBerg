<h1 align="left">
  <img src="fuzzberg-icon.png" alt="FuzzBerg Icon" width="45" height="30" style="margin-right: 12px; vertical-align: middle;">
  FuzzBerg
</h1>
<p>
  A hybrid fuzzer <b>(structured + black-box)</b> for Apache Iceberg, and other file-format database readers 
</p>


<br>

## Description

FuzzBerg was built to secure the launch of [Firebolt Core](https://www.firebolt.io/core) and [READ_ICEBERG](https://docs.firebolt.io/reference-sql/functions-reference/table-valued/read_iceberg), and helped us overcome the challenges of fuzzing complex database interfaces, such as `Table Valued Functions` and `COPY_FROM`. 

It quickly proved its worth by discovering <b> 5 critical bugs </b> across all our TVF formats- including `READ_ICEBERG`.

<br>

### Features

<br>

- Fuzz data ingestion interfaces (e.g., `COPY FROM`, TVFs: `read_iceberg()`, `read_csv()`, `read_parquet()`)
- No need to write/maintain unit-level harnesses
- Currently supported formats: `Iceberg`, `CSV`, `Parquet`
 - Easily extensible for new targets and file-formats
  > **Note:** Iceberg fuzzing is currently supported for S3-based readers only. Use a compatible S3 interface such as [Minio](https://www.min.io/) to fuzz on Linux platforms.


Mutations are both structure-aware and randomised with [libRadamsa](https://gitlab.com/akihe/radamsa) (no coverage guidance), seeded by a [Mersenne Twister](https://github.com/ESultanik/mtwister) PRNG.

<br>

## Fuzz Your Database

<br>

- Place target code under `src/Databases/<database>.{cpp,h}`
- Add `<database>.cpp` to `CMakeLists.txt`
- Implement a target DB class, and override the following base interfaces:
  - `DatabaseHandler::ForkTarget()` : to launch target as a child of the fuzzer
  - `DatabaseHandler::fuzz()` : call the relevant file-format fuzzer
- Create a JSON file under `queries/<database>/*.json` listing relevant queries for your target. 
  - Only add queries for file-formats currently supported by the fuzzer (`CSV`, `Parquet`, `Iceberg`).
<br>

## Build Instructions

<br>

1. Install `libcurl4-openssl-dev` (Ubuntu/Debian). See [details](https://ec.haxx.se/install/linux.html).
2. Build with CMake & Ninja:
   ```sh
   mkdir build && cd build
   cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 -G Ninja ../
   ninja -j<N> fuzzberg
   ```

> **Note:** For efficient fuzzing, compile your target with [AddressSanitizer](https://github.com/google/sanitizers/wiki/addresssanitizer). Also, fuzzing a `Release` build is recommended (where invariants like `DCHECK` is compiled out).

<br>

## License

FuzzBerg is released under the [Apache License 2.0](LICENSE). See the [LICENSE](LICENSE) file for details.

<br>

## Usage

<br>

```sh
Usage: ./fuzzberg [OPTIONS]

Required:
  -d, --database NAME         Database name (e.g., duckdb, firebolt)
  -f, --format FORMAT         File format (csv, parquet, iceberg)
  -u, --url URL               Database server URL
  -i, --input DIR             Input corpus directory
  -o, --output DIR            Output (crash) directory
  -b, --bin PATH              Path to the target binary
  -m, --mutate FILE           Mutation payload file
  -q, --queries FILE          JSON file containing queries (see queries/<database>/*.json)
Optional:
  -t, --auth TOKEN            Authentication token (JWT)
  -B, --bucket BUCKET_NAME    S3 bucket name for Iceberg (required if --format=iceberg)
```

<br>

## Fuzzing Examples

<br>

### [Firebolt `READ_ICEBERG()`](https://docs.firebolt.io/reference-sql/functions-reference/table-valued/read_iceberg)


```sh
./fuzzberg \
  -i ./corpus_iceberg \
  -o ./crash \
  --database=firebolt \
  --bucket iceberg-fuzzing \
  --format=iceberg \
  --url=http://localhost:3473 \
  -m /data/minio/iceberg-fuzzing/metadata \
  -q fb_core_iceberg.json \
  -b ./firebolt-core
```

#### Sample output:
```
Adding query: SELECT * FROM READ_ICEBERG(url => 's3://iceberg-fuzzing/metadata/v3.metadata.json');
Loaded 1 queries from ./fb_core_iceberg.json
Checking connection to server...
starting up
...

******** Starting structured metadata fuzzing *********

Key: "current-snapshot-id", Original Value: 4676137652994606811, Mutated Value: 170141183460469231731687303715884105727


Query :  SELECT * FROM READ_ICEBERG(url => 's3://iceberg-fuzzing/metadata/v3.metadata.json');

Response: {
  "errors": [
    {
      "description": "Exception: Value too large."
    }
  ],
  "query": {
    "query_id": "c1c6a6c5-c612-438d-a574-ecc563303247",
    "query_label": null,
    "request_id": "54bd0463-c45b-448d-82ea-efd487c95e6e"
  },
  "statistics": {
    "elapsed": 0.0
  }
}

Key: "current-schema-id", Original Value: 0, Mutated Value: 128


Query :  SELECT * FROM READ_ICEBERG(url => 's3://iceberg-fuzzing/metadata/v3.metadata.json');

Response: {
  "errors": [
    {
      "description": "There is no schema with \"schema-id\" that matches \"current-schema-id\" in metadata"
    }
  ],
  "query": {
    "query_id": "28a2b98f-e599-4310-953e-372f00732aa0",
    "query_label": null,
    "request_id": "2ce997c2-5a20-43cc-88bf-7b78f5cae5a7"
  },
  "statistics": {
    "elapsed": 0.0
  }
}
```
 

<br>

### [Firebolt `READ_PARQUET()`](https://docs.firebolt.io/reference-sql/functions-reference/table-valued/read_parquet)

```sh
./fuzzberg \
  -i ./corpus_parquet \
  -o ./crash \
  --database=firebolt \
  --format=parquet \
  --url=http://localhost:3473 \
  -m /data/minio/black-box-fuzzer/ \
  -q fb_core_parquet.json \
  -b ./firebolt-core
```

#### Sample output:
```
Query : SELECT * FROM READ_PARQUET(url => 's3://black-box-fuzzer/fuzz.parquet');

Response: {
  "errors": [
    {
      "description": "Error reading column 'l_partkey' in row group 0 of 's3://black-box-fuzzer/fuzz.parquet': IOError: Corrupt snappy compressed data."
    }
  ],
  "query": {
    "query_id": "63be960d-b218-41b6-afa1-dd5590d2d781",
    "query_label": null,
    "request_id": "b0404488-579f-41d3-b8cd-6e6f30fe2689"
  },
  "statistics": {
    "elapsed": 0.016309347
  }
}
```

<br>

### [DuckDB `read_csv()`](https://duckdb.org/docs/stable/data/csv/overview) (with HTTP Server Extension)


```sh
./fuzzberg \
  -i ./corpus/csv \
  -o ./crash \
  --database=duckdb \
  --format=csv \
  --url=http://localhost:9999 \
  -m /tmp \
  -q duckdb_csv.json \
  -b ./duckdb-extension-httpserver/build/release/duckdb \
  -- \
  --ascii \
  --init /home/ubuntu/ddb/duckdb/init.sql \
  --batch
```

#### Sample output:
```
Adding query: SELECT * FROM read_csv('/tmp/fuzz.csv');

Adding query: SELECT * FROM read_csv('/tmp/fuzz.csv',header = true,delim = '|',allow_quoted_nulls = false, ignore_errors=false);

Loaded 2 queries from queries/duckdb_csv.json

Checking connection to server...

┌──────────────────────────────────────┐
│ httpserve_start('0.0.0.0', 9999, '') │
│               varchar                │
├──────────────────────────────────────┤
│ HTTP server started on 0.0.0.0:9999  │
└──────────────────────────────────────┘


Query : SELECT * FROM read_csv('/tmp/fuzz.csv',header = true,delim = '|',allow_quoted_nulls = false, ignore_errors=false);

Response: {"c9223372036854775809,c2,c3,c5,c5,c6,c7,c128,c9,c10,c11,c12,c13,c14,c15":"t,2�,,,,,,�,,,,,I ,,,c4294967296,c6,c212,c8,c9,c10,c�,c12,c13"}
{"c9223372036854775809,c2,c3,c5,c5,c6,c7,c128,c9,c10,c11,c12,c13,c14,c15":"e,QrUe,10,100,-32642,-263749625369741"}


Query : SELECT * FROM read_csv('/tmp/fuzz.csv');

Response: Invalid Input Error: CSV Error on Line: 1
Invalid unicode (byte sequence mismatch) detected. This file is not utf-8 encoded.

Possible Solution: Set the correct encoding, if available, to read this CSV File (e.g., encoding='UTF-16')
....
```

<br>

## Reporting Bugs

<br>

If you discover a bug, please report it via GitHub Issues or contact the maintainers directly.