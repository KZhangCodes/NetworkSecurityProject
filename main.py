import hashlib
import time
from multiprocessing import Pool, cpu_count
import math

def load_lines(file_path):
    with open(file_path, 'r', encoding='utf-8-sig') as infile:
        return [line.strip() for line in infile.readlines()]

def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()

#worker functions
def dictionary_bruteforce(args):
    subset_words, all_words, target_hashes = args
    cracked_passwords = {}
    target_hash_set = set(target_hashes) # set lookup

    for first_word in subset_words:

        #test single word
        single_word_hash = sha1_hash(first_word)
        if single_word_hash in target_hash_set:
            cracked_passwords[single_word_hash] = first_word

        #test two word combo in subset
        for second_word in subset_words:
            two_word = first_word + second_word
            two_word_hash = sha1_hash(two_word)

            if two_word_hash in target_hash_set:
                cracked_passwords[two_word_hash] = two_word
            #three word combo in subset
            for third_word in subset_words:
                three_word = first_word + second_word + third_word
                three_word_hash = sha1_hash(three_word)

                if three_word_hash in target_hash_set:
                    cracked_passwords[three_word_hash] = three_word

    return cracked_passwords

def numeric_bruteforce(args):
    range_start, range_end, target_hashes = args
    cracked_passwords = {}
    target_hash_set = set(target_hashes)

    zero_padding = ["0", "00", "000", "0000", "00000", "000000", "0000000", "00000000",]

    for zeros in zero_padding:
        hash_value = sha1_hash(zeros)
        if hash_value in target_hash_set:
            cracked_passwords[hash_value] = zeros

    for number in range(int(range_start), int(range_end)):
        candidate = str(number)
        hash_value = sha1_hash(candidate)
        if hash_value in target_hash_set:
            cracked_passwords[hash_value] = candidate

    return cracked_passwords

def main():
    start_time = time.time()

    dictionary_words = load_lines("dictionary.txt")
    passwords = load_lines("passwords.txt")
    #hash -> userid
    hash_to_user_id = {
        line.split()[1]: line.split()[0]
        for line in passwords
    }

    target_hash_list = list(hash_to_user_id.keys())

    #multiprocess setup
    num_processes = cpu_count()

    #split dictionary
    subset_size = math.ceil(len(dictionary_words) / num_processes)
    dictionary_chunks = [dictionary_words[i:i + subset_size] for i in range(0, len(dictionary_words), subset_size)]

    dict_worker_args = [(chunk, dictionary_words, target_hash_list) for chunk in dictionary_chunks]

    #numeric ranges
    max_numeric_value = 1_000_000_000
    numeric_block_size = max_numeric_value // num_processes

    numeric_ranges = [(i * numeric_block_size, (i + 1) * numeric_block_size) for i in range(num_processes)]
    numeric_ranges[-1] = (numeric_ranges[-1][0], max_numeric_value)

    numeric_worker_args = [(start, end, target_hash_list)for (start, end) in numeric_ranges]

    #dict + numeric in parallel
    with Pool(processes=num_processes) as pool:
        dict_results = pool.map(dictionary_bruteforce, dict_worker_args)
        numeric_results = pool.map(numeric_bruteforce, numeric_worker_args)

    #merge returns from workers
    cracked_results = {}
    for partial in dict_results:
        cracked_results.update(partial)

    for partial in numeric_results:
        cracked_results.update(partial)

    #hash -> plaintext
    for cracked_hash, cracked_password in cracked_results.items():
        user_id = hash_to_user_id[cracked_hash]
        print(f"User {user_id}: {cracked_hash} -> {cracked_password}")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"\nExecution time: {elapsed_time:.1f} seconds")

if __name__ == "__main__":
    main()
