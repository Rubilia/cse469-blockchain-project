all:
    cp main.py bchoc
    chmod +x bchoc

run:
    ./bchoc

clean:
    rm -f blockchain.dat
