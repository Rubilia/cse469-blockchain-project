# CSE469-Group Project: Blockchain Chain of Custody
Group 22: Ilia Rubashkin 1222860600,  Ian Mello 1213986903 , Brenen Krock 1217521461, Jeffrey Sellers 1222044408

## Build the Program
This copies the main.py to bchoc and makes it executable.
```bash
make 
```
## Initialize the Blockchain:
Initialization (init): 
Creates a new blockchain file if none exists and adds a "Genesis block" to start the chain. If a blockchain file already exists, it confirms that the Genesis block is present.
```bash
./bchoc init
```
## Add Evidence:
Adding Evidence (add): 
Adds a new block to the blockchain for each evidence item provided. Each block includes a unique case ID, evidence ID, timestamp, creator, and status (CHECKEDIN). Prevents duplicate evidence IDs.
```bash
./bchoc add -c <case_id> -i <item_id> -g <creator> -p <password>
```
## Check Out Evidence:
Checking Out Evidence (checkout):
Updates the status of an existing evidence item to CHECKEDOUT. Requires the item to be in a CHECKEDIN state. Records the action with the owner and a timestamp.
```bash
./bchoc checkout -i <item_id> -p <password>
```
## Check In Evidence:
Checking In Evidence (checkin): 
Updates the status of an evidence item back to CHECKEDIN. Requires the item to be in a CHECKEDOUT state. Records the action with a timestamp.
```bash
./bchoc checkin -i <item_id> -p <password>
```
## Remove Evidence:
Removing Evidence (remove): 
Changes the status of an evidence item to DISPOSED, DESTROYED, or RELEASED. Requires the item to be in a CHECKEDIN state. For RELEASED, additional details about the lawful owner must be provided.
```bash
./bchoc remove -i <item_id> -y <reason> -p <password>
```
## Verify Blockchain:
Verifying the Blockchain (verify): 
Ensures the integrity of the blockchain by validating: The hash of each block matches the previous block's hash. No entries are added after an item is removed. No duplicate parent blocks or broken hash links exist.
```bash
./bchoc verify
```
## Show Evidence for a Case:
Viewing Blockchain Information (show): Displays cases, evidence items, or the history of actions on an item or case. History can be filtered by number of entries or reversed order. Encrypted values are shown unless the correct password is provided.
```bash
./bchoc show cases
```
## Show History:
This command provides a detailed history of all actions associated with specific evidence items or cases in the blockchain. Can display actions for a specific case_id, a specific item_id, or both. Displays the type of action (CHECKEDIN, CHECKEDOUT, etc.), timestamps, and relevant metadata for each block. Can display history in chronological order (oldest to newest) or reverse chronological order (newest to oldest) with the -r flag. The -n flag allows users to specify the maximum number of entries to display. With a valid password, encrypted details like case IDs and evidence IDs are decrypted. Without a password, encrypted values are displayed.
```bash
./bchoc show history -c <case_id> -i <item_id> -p <password>
```



#### Generative AI Acknowledgment: Portions of the code in this project were generated with assistance from ChatGPT, an AI tool developed by OpenAI. Reference: OpenAI. (2024). ChatGPT [Large language model]. openai.com/chatgpt

