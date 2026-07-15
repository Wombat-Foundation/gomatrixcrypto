CUCKOO_SRC := ../../../external/cuckoo/src/cuckoo
CRYPTO_SRC := ../../../external/cuckoo/src/crypto
CXXFLAGS   := -O3 -std=c++11 -DEDGEBITS=29 -DPROOFSIZE=42 -DNSIPHASH=1 -I$(CUCKOO_SRC)
LDFLAGS    := -pthread

BIN := ../cuckoo_solve_29_42

.PHONY: all clean

all: $(BIN)

$(BIN): solve_main.cpp $(CUCKOO_SRC)/mean.hpp
	$(CXX) $(CXXFLAGS) solve_main.cpp $(CRYPTO_SRC)/blake2b-ref.c -o $(BIN) $(LDFLAGS)

clean:
	rm -f $(BIN)
