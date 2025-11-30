import hashlib
import time

def load_lines(file_path):
    with open(file_path, 'r', encoding='utf-8-sig') as infile:
        return [line.strip() for line in infile.readlines()]

def sha1_hash(text):
    return hashlib.sha1(text.encode()).hexdigest()

def dictionary_bruteforce(dictionary_words, target_hashes):
    cracked_passwords = {}
    target_hash_set = set(target_hashes)

    for first_word in dictionary_words:

        #test single word
        single_word_hash = sha1_hash(first_word)
        if single_word_hash in target_hash_set:
            cracked_passwords[single_word_hash] = first_word

        #test two word combo
        for second_word in dictionary_words:
            combined_word = first_word + second_word
            combined_word_hash = sha1_hash(combined_word)

            if combined_word_hash in target_hash_set:
                cracked_passwords[combined_word_hash] = combined_word

    return cracked_passwords

def main():
    start_time = time.time()

    dictionary_words = load_lines("dictionary.txt")
    passwords = load_lines("passwords.txt")

    hash_to_user_id = {
        line.split()[1]: line.split()[0]
        for line in passwords
    }

    target_hash_list = list(hash_to_user_id.keys())

    cracked_results = dictionary_bruteforce(dictionary_words, target_hash_list)

    for cracked_hash, cracked_password in cracked_results.items():
        print(f"User {hash_to_user_id[cracked_hash]}: {cracked_hash} -> {cracked_password}")

    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"\nExecution time: {elapsed_time:.1f} seconds")

if __name__ == "__main__":
    main()

