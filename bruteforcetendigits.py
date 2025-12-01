import hashlib
import time
from multiprocessing import Pool, cpu_count

def load_lines(file_path):
    with open(file_path, 'r', encoding='utf-8-sig') as infile:
        return [line.strip() for line in infile.readlines()]

def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()

def numeric_bruteforce(args):
    range_start, range_end, target_hashes = args
    cracked_passwords = {}
    target_hash_set = set(target_hashes)

    for number in range(int(range_start), int(range_end)):
        combination = str(number)
        hash_value = sha1_hash(combination)
        if hash_value in target_hash_set:
            cracked_passwords[hash_value] = combination

    return cracked_passwords

def main():
    start_time = time.time()

    passwords = load_lines("passwords.txt")
    hash_to_user_id = {line.split()[1]: line.split()[0] for line in passwords}
    target_hash_list = list(hash_to_user_id.keys())
    num_processes = cpu_count()
    max_numeric_value = 6_000_000_000
    numeric_block_size = max_numeric_value // num_processes

    numeric_ranges = [(i * numeric_block_size, (i + 1) * numeric_block_size) for i in range(num_processes)]
    numeric_ranges[-1] = (numeric_ranges[-1][0], max_numeric_value)
    numeric_worker_args = [(start, end, target_hash_list) for (start, end) in numeric_ranges]

    with Pool(processes=num_processes) as pool:
        numeric_results = pool.map(numeric_bruteforce, numeric_worker_args)

    cracked_results = {}
    for partial in numeric_results:
        cracked_results.update(partial)

    for cracked_hash, cracked_password in cracked_results.items():
        user_id = hash_to_user_id[cracked_hash]
        print(f"User {user_id}: {cracked_hash} -> {cracked_password}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nExecution time: {elapsed_time:.1f} seconds")

if __name__ == "__main__":
    main()

