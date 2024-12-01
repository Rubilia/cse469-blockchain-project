import argparse
import os
from blockchain import BlockChain

# need to more methods for : init, add, checkout, checkin, verify and show



def main():
    parser = argparse.ArgumentParser(description="Chain of Custody Blockchain")
    parser.add_argument("command", choices=["init", "add", "checkout", "checkin", "verify", "show"], help="Command to execute")
    parser.add_argument("-c", "--case_id", help="Case ID")
    parser.add_argument("-i", "--evidence_id", type=int, help="Evidence ID")
    parser.add_argument("-g", "--author", help="Author/Creator")
    parser.add_argument("-p", "--password", help="Password")
    args = parser.parse_args()

    file_path = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")
    blockchain = BlockChain(file_path)

    if args.command == "init":
        blockchain.init_blockchain()
    elif args.command == "add":
        if args.case_id and args.evidence_id and args.author:
            blockchain.add_entry(args.case_id, args.evidence_id, args.author)
        else:
            print("Error: Missing arguments for 'add' command.")
    elif args.command == "checkout":
        if args.evidence_id and args.password:
            blockchain.checkout_item(args.evidence_id, args.password)
        else:
            print("Error: Missing arguments for 'checkout' command.")
    elif args.command == "checkin":
        if args.evidence_id and args.password:
            blockchain.checkin_item(args.evidence_id, args.password)
        else:
            print("Error: Missing arguments for 'checkin' command.")
    elif args.command == "verify":
        valid, message = blockchain.verify_chain()
        print(message)
    elif args.command == "show":
        # Implement show logic here
        pass
    else:
        print("Invalid command.")

if __name__ == "__main__":
    main()
