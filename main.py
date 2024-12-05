#!/usr/bin/python3

import os
import argparse

from blockchain import BlockChain


def main():
    parser = argparse.ArgumentParser(description="Chain of Custody Blockchain")
    parser.add_argument("command", choices=["init", "add", "checkout", "checkin", "remove", "verify", "show"], help="Command to execute")
    parser.add_argument("subcommand", nargs='?', help="Subcommand for 'show' command")
    parser.add_argument("-c", "--case_id", help="Case ID")
    parser.add_argument("-i", "--evidence_id", action='append', type=int, help="Evidence ID")
    parser.add_argument("-g", "--author", help="Author/Creator")
    parser.add_argument("-p", "--password", help="Password")
    parser.add_argument("-y", "--why", help="Password")
    parser.add_argument('-n', '--num_entries', type=int, help="Number of entries to show")
    parser.add_argument('-r', '--reverse', action='store_true', help="Reverse the order of entries")

    args = parser.parse_args()

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    blockchain = BlockChain(file_path)

    if args.command == "show":
        if args.subcommand == "items":
            return blockchain.show_items(args.case_id)
        elif args.subcommand == "cases":
            return blockchain.show_cases()
        elif args.subcommand == "history" and (not args.evidence_id or len(args.evidence_id) == 1):
            return blockchain.show_history(args.case_id, args.evidence_id[0] if args.evidence_id else args.evidence_id, args.num_entries, args.reverse, args.password)
        else:
            print("Error: 'show' command requires 'items', 'cases' or 'history' as subcommand.")
            exit(1)

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
                blockchain.checkout_entry(args.evidence_id[0], args.password)
            else:
                print("Error: Wrong arguments for 'checkout' command.")
                exit(2)
        case "checkin":
            if args.evidence_id and len(args.evidence_id) == 1 and args.password:
                blockchain.checkin_entry(args.evidence_id[0], args.password)
            else:
                print("Error: Wrong arguments for 'checkin' command.")
        case "remove":
            if args.evidence_id and len(args.evidence_id) == 1 and args.why and args.password:
                blockchain.remove_entry(args.evidence_id[0], args.why, args.password)
            else:
                print("Error: Wrong arguments for 'remove' command.")
        case "verify":
            blockchain.verify_chain()
        case "show":
            # Implement show logic here
            pass
        case _:
            print("Invalid command.")

if __name__ == "__main__":
    main()
