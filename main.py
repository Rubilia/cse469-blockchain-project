#!/usr/bin/python3

import os
import argparse

from blockchain import BlockChain


def main():
    parser = argparse.ArgumentParser(description="Chain of Custody Blockchain")
    parser.add_argument("command", choices=["init", "add", "checkout", "checkin", "verify", "show"], help="Command to execute")
    parser.add_argument("-c", "--case_id", help="Case ID")
    parser.add_argument("-i", "--evidence_id", action='append', type=int, help="Evidence ID")
    parser.add_argument("-g", "--author", help="Author/Creator")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-y", "--why", help="Password")
    args = parser.parse_args()

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    blockchain = BlockChain(file_path)

    match args.command:
        case"init":
            blockchain.init_blockchain(verbose=True)
        case "add":
            if args.case_id and args.evidence_id and args.author and args.password:
                blockchain.add_entry(args.case_id, args.evidence_id, args.author, args.password)
            else:
                print("Error: Wrong arguments for 'add' command.")
                exit(1)
        case "checkout":
            if args.evidence_id and len(args.evidence_id) == 1 and args.password:
                blockchain.checkout_item(args.evidence_id[0], args.password)
            else:
                print("Error: Wrong arguments for 'checkout' command.")
                exit(2)
        case "checkin":
            if args.evidence_id and args.password:
                blockchain.checkin_item(args.evidence_id, args.password)
            else:
                print("Error: Wrong arguments for 'checkin' command.")
        case "verify":
            valid, message = blockchain.verify_chain()
            print(message)
        case "show":
            # Implement show logic here
            pass
        case _:
            print("Invalid command.")

if __name__ == "__main__":
    main()
