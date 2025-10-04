# Description
This CUDA-based password cracker performs brute-force attacks on SHA1, SHA256 and MD5 hashes by leveraging GPU parallelism. Given a target hash and a password length (up to 8 characters), it systematically tests all possible combinations of printable ASCII characters across thousands of CUDA threads. Each thread computes a candidate password's hash and compares it to the target, terminating once a match is found and printing the recovered password.

# Compile Commands

nvcc -O3 -arch=sm_52 -o pwcrk yourfilename.cu pwcrk-sha256

This will produce a binary called pwcrk.

# Usage

The binary takes in a hex-encoded SHA1 or MD5 hash and attempts to brute-force it:
bash

./pwcrk <hash_value> <password_length> <hash_type>

Example (SHA1 hash for abc123 = 6367c48dd193d56ea7b0baad25b19455e529f5ee):

./pwcrk 6367c48dd193d56ea7b0baad25b19455e529f5ee 6 sha1

For MD5:

./pwcrk e99a18c428cb38d5f260853678922e03 6 md5

# Disclaimer

This tool is provided for **educational purposes only**. The author does not condone or support illegal activity. Any misuse of this tool is **strictly forbidden** and is the sole responsibility of the user.

# License

This software is subject to a license, please refer to the license file for more information.
