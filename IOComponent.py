

class IOUtils:

    '''
    
    WriteToFile:
    Takes in a blockchain list containing 1 or more blockchain entries(there will always be 1, thew inital block)
    Each entry in the blockchain will be encrypted and stored in binary file.

    @arguments:

    Steps:
    1. Take in the blockchain object.
    2. Foreach entry in blockchain:
        a. Encrypt feilds using encrpyt util function
        b. Write to file in the order specified using struct
    3. return true if sucessful
    
    
    '''
    @staticmethod
    def writeToFile():

        '''
        
        ReadFile:
        Reads in blockchain from file and sends the full blockchain object(if there is one)

        Steps:
        1. setup stream for file
        2. for each theoredical blockchain entry:
            a. read in the block and interpret
            b. create block entry and add it to the blockchain
        3. return blockchain object
        
        
        '''

    @staticmethod
    def ReadFile():